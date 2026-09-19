"""SCIM v2 endpoint for Entra user provisioning (hand-rolled, no DRF).

Every JSON view is @csrf_exempt (the global CsrfViewMiddleware would reject
the bearer-authenticated POSTs); the browser settings page is NOT exempted.
"""

import hmac
import json
import logging
import re

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import get_user_model
from django.contrib.auth.mixins import LoginRequiredMixin, UserPassesTestMixin
from django.db import IntegrityError
from django.http import JsonResponse
from django.shortcuts import redirect, render
from django.views import View
from django.views.decorators.csrf import csrf_exempt

from audit.middleware import log_action
from audit.models import AuditLog
from .models import ScimConfig
from .serializers import LIST_SCHEMA, USER_SCHEMA, user_to_scim

logger = logging.getLogger(__name__)

User = get_user_model()

FILTER_RE = re.compile(r'^(userName|externalId)\s+eq\s+"([^"]*)"$', re.IGNORECASE)


# ── Auth + JSON plumbing ─────────────────────────────────────────────────────


def _authenticate(request):
    """Validate the bearer token; returns the config or None."""
    config = ScimConfig.get_config()
    header = request.META.get('HTTP_AUTHORIZATION', '')
    if not (config.enabled and header.startswith('Bearer ')):
        return None
    presented = header[len('Bearer '):].strip()
    expected = config.get_effective_token()
    if not expected or not hmac.compare_digest(presented, expected):
        return None
    return config


def _scim_error(status, detail, scim_type=None) -> JsonResponse:
    body = {
        'schemas': ['urn:ietf:params:scim:api:messages:2.0:Error'],
        'status': str(status),
        'detail': detail,
    }
    if scim_type:
        body['scimType'] = scim_type
    return JsonResponse(body, status=status, content_type='application/scim+json')


def _unauthorized() -> JsonResponse:
    resp = _scim_error(401, 'Invalid or missing bearer token')
    resp['WWW-Authenticate'] = 'Bearer'
    return resp


def _read_body(request):
    try:
        return json.loads(request.body.decode('utf-8') or '{}')
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None


# ── Users collection ──────────────────────────────────────────────────────────


@csrf_exempt
def users_collection(request):
    if not _authenticate(request):
        return _unauthorized()

    if request.method == 'GET':
        qs = User.objects.order_by('id')
        filter_expr = request.GET.get('filter')
        if filter_expr:
            match = FILTER_RE.match(filter_expr)
            if not match:
                return _scim_error(400, 'Unsupported filter expression', 'invalidFilter')
            attr, value = match.group(1).lower(), match.group(2)
            if attr == 'username':
                qs = qs.filter(username__iexact=value)
            else:
                qs = qs.filter(entra_object_id=value)

        try:
            start_index = max(1, int(request.GET.get('startIndex', 1)))
        except (ValueError, TypeError):
            start_index = 1
        try:
            count = min(1000, max(1, int(request.GET.get('count', 100))))
        except (ValueError, TypeError):
            count = 100

        total = qs.count()
        page = qs[(start_index - 1):(start_index - 1) + count]
        return JsonResponse({
            'schemas': [LIST_SCHEMA],
            'totalResults': total,
            'startIndex': start_index,
            'itemsPerPage': len(page),
            'Resources': [user_to_scim(u) for u in page],
        }, content_type='application/scim+json')

    if request.method == 'POST':
        data = _read_body(request)
        if data is None:
            return _scim_error(400, 'Request body is not valid JSON', 'invalidSyntax')

        external_id = (data.get('externalId') or '').strip()
        if not external_id:
            # Guard BEFORE any lookup: get_or_create on a None unique key
            # would match unrelated local accounts.
            return _scim_error(400, 'externalId is required', 'invalidValue')

        user_name = (data.get('userName') or '').split('@')[0].strip()
        if not user_name:
            return _scim_error(400, 'userName is required', 'invalidValue')
        name = data.get('name') or {}
        emails = data.get('emails') or []
        email = emails[0].get('value', '') if emails else ''
        active = data.get('active', True)

        defaults = {
            'username': user_name,
            'email': email,
            'first_name': name.get('givenName', ''),
            'last_name': name.get('familyName', ''),
            'is_active': bool(active),
        }
        try:
            user, created = User.objects.get_or_create(
                entra_object_id=external_id, defaults=defaults)
            if not created:
                # Upsert semantics: converge on retries
                user.username = user_name
                user.email = email or user.email
                user.first_name = name.get('givenName', '')
                user.last_name = name.get('familyName', '')
                user.is_active = bool(active)
                user.save()
        except IntegrityError:
            return _scim_error(409, f"userName '{user_name}' is already taken "
                               'by a different account', 'uniqueness')

        log_action(
            actor=None,
            action=AuditLog.Action.SCIM_USER_PROVISIONED,
            target_type='User',
            target_id=user.pk,
            details={'externalId': external_id, 'userName': user_name,
                     'created': created},
            request=request,
        )
        return JsonResponse(user_to_scim(user), status=201 if created else 200,
                            content_type='application/scim+json')

    return _scim_error(405, 'Method not allowed')


# ── User resource ─────────────────────────────────────────────────────────────


def _get_user_or_404(resource_id):
    try:
        user = User.objects.filter(pk=int(resource_id)).first()
        if user:
            return user
    except (ValueError, TypeError):
        pass
    return User.objects.filter(entra_object_id=resource_id).first()


def _apply_attributes(user, data, changed):
    """Apply a SCIM attribute dict to a user; record changed field names."""
    if 'active' in data:
        user.is_active = bool(data['active'])
        changed.append('active')
    if data.get('userName'):
        user.username = data['userName'].split('@')[0].strip()
        changed.append('userName')
    name = data.get('name') or {}
    if 'givenName' in name:
        user.first_name = name['givenName']
        changed.append('name.givenName')
    if 'familyName' in name:
        user.last_name = name['familyName']
        changed.append('name.familyName')
    emails = data.get('emails') or []
    if emails and emails[0].get('value'):
        user.email = emails[0]['value']
        changed.append('emails')


def _apply_patch(user, operations):
    changed = []
    for op in operations:
        op_name = op.get('op', '').lower()
        if op_name not in ('replace', 'add', 'remove'):
            continue
        if op_name == 'remove':
            if op.get('path') == 'active':
                user.is_active = False
                changed.append('active')
            continue
        value = op.get('value')
        if isinstance(value, dict):
            _apply_attributes(user, value, changed)
        else:
            path = op.get('path')
            if path == 'active':
                user.is_active = bool(value)
                changed.append('active')
            elif path == 'userName' and value:
                user.username = str(value).split('@')[0].strip()
                changed.append('userName')
            # Unknown paths (enterprise extensions etc.) are ignored
    return changed


@csrf_exempt
def user_resource(request, resource_id):
    if not _authenticate(request):
        return _unauthorized()

    user = _get_user_or_404(resource_id)
    if user is None:
        return _scim_error(404, f'User {resource_id} not found')

    if request.method == 'GET':
        return JsonResponse(user_to_scim(user), content_type='application/scim+json')

    if request.method == 'DELETE':
        if user.is_active:
            user.is_active = False
            user.save(update_fields=['is_active'])
            log_action(
                actor=None,
                action=AuditLog.Action.SCIM_USER_DEPROVISIONED,
                target_type='User',
                target_id=user.pk,
                details={'externalId': user.entra_object_id},
                request=request,
            )
        return JsonResponse({}, status=204)

    data = _read_body(request)
    if data is None:
        return _scim_error(400, 'Request body is not valid JSON', 'invalidSyntax')

    if request.method == 'PATCH':
        changed = _apply_patch(user, data.get('Operations') or [])
        if changed:
            try:
                user.save()
            except IntegrityError:
                return _scim_error(409, 'userName already taken by another account',
                                   'uniqueness')
            log_action(
                actor=None,
                action=AuditLog.Action.SCIM_USER_UPDATED,
                target_type='User',
                target_id=user.pk,
                details={'changed': changed, 'active': user.is_active},
                request=request,
            )
        return JsonResponse({}, status=204)

    if request.method == 'PUT':
        external_id = (data.get('externalId') or '').strip()
        if external_id and external_id != user.entra_object_id:
            return _scim_error(400, 'externalId cannot be changed', 'mutability')
        changed = []
        _apply_attributes(user, data, changed)
        try:
            user.save()
        except IntegrityError:
            return _scim_error(409, 'userName already taken by another account',
                               'uniqueness')
        log_action(
            actor=None,
            action=AuditLog.Action.SCIM_USER_UPDATED,
            target_type='User',
            target_id=user.pk,
            details={'changed': changed, 'active': user.is_active},
            request=request,
        )
        return JsonResponse(user_to_scim(user), content_type='application/scim+json')

    return _scim_error(405, 'Method not allowed')


# ── Groups + discovery stubs ──────────────────────────────────────────────────


@csrf_exempt
def groups_collection(request):
    if not _authenticate(request):
        return _unauthorized()
    if request.method == 'GET':
        return JsonResponse({
            'schemas': [LIST_SCHEMA],
            'totalResults': 0,
            'startIndex': 1,
            'itemsPerPage': 0,
            'Resources': [],
        }, content_type='application/scim+json')
    return _scim_error(501, 'Group provisioning is not supported')


@csrf_exempt
def group_resource(request, resource_id):
    if not _authenticate(request):
        return _unauthorized()
    if request.method == 'GET':
        return _scim_error(404, f'Group {resource_id} not found')
    return _scim_error(501, 'Group provisioning is not supported')


@csrf_exempt
def service_provider_config(request):
    if not _authenticate(request):
        return _unauthorized()
    return JsonResponse({
        'schemas': ['urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig'],
        'patch': {'supported': True},
        'bulk': {'supported': False, 'maxOperations': 0, 'maxPayloadSize': 0},
        'filter': {'supported': True, 'maxResults': 200},
        'changePassword': {'supported': False},
        'sort': {'supported': False},
        'etag': {'supported': False},
        'authenticationSchemes': [
            {'type': 'oauthbearertoken', 'name': 'OAuth Bearer Token',
             'description': 'Bearer token from PAM SCIM Settings'},
            {'type': 'httpbasic', 'name': 'HTTP Basic'},
        ],
    }, content_type='application/scim+json')


@csrf_exempt
def schemas(request):
    if not _authenticate(request):
        return _unauthorized()
    return JsonResponse({
        'schemas': ['urn:ietf:params:scim:api:messages:2.0:ListResponse'],
        'totalResults': 1,
        'Resources': [{
            'id': USER_SCHEMA,
            'name': 'User',
            'description': 'User Account',
            'attributes': [
                {'name': 'userName', 'type': 'string', 'required': True,
                 'uniqueness': 'server'},
                {'name': 'name', 'type': 'complex'},
                {'name': 'emails', 'type': 'complex', 'multiValued': True},
                {'name': 'externalId', 'type': 'string', 'uniqueness': 'server'},
                {'name': 'active', 'type': 'boolean'},
            ],
        }],
    }, content_type='application/scim+json')


@csrf_exempt
def schema_resource(request, schema_id):
    if not _authenticate(request):
        return _unauthorized()
    if schema_id != USER_SCHEMA:
        return _scim_error(404, f'Schema {schema_id} not found')
    return schemas(request)


@csrf_exempt
def resource_types(request):
    if not _authenticate(request):
        return _unauthorized()
    return JsonResponse({
        'schemas': ['urn:ietf:params:scim:api:messages:2.0:ListResponse'],
        'totalResults': 1,
        'Resources': [{
            'schemas': ['urn:ietf:params:scim:schemas:core:2.0:ResourceType'],
            'id': 'User',
            'name': 'User',
            'endpoint': '/scim/v2/Users',
            'schema': USER_SCHEMA,
        }],
    }, content_type='application/scim+json')


# ── Browser settings page (NOT csrf-exempt) ───────────────────────────────────


class SCIMSettingsView(LoginRequiredMixin, UserPassesTestMixin, View):
    """Staff page for configuring the SCIM endpoint."""

    def test_func(self):
        return self.request.user.is_staff or self.request.user.is_admin_user

    def get(self, request):
        config = ScimConfig.get_config()
        return render(request, 'pam/scim_settings.html', {
            'config': config,
            'tenant_url': self._tenant_url(request),
            'config_has_base_url': bool(getattr(settings, 'PAM_BASE_URL', '')),
        })

    def _tenant_url(self, request):
        base = getattr(settings, 'PAM_BASE_URL', '')
        if base:
            return f'{base.rstrip("/")}/scim/v2/'
        return request.build_absolute_uri('/scim/v2/')

    def post(self, request):
        config = ScimConfig.get_config()
        config.enabled = request.POST.get('enabled') == 'on'
        raw_token = request.POST.get('bearer_token', '').strip()
        if raw_token:
            config.set_bearer_token(raw_token)
        config.configured_by = request.user
        config.save()
        if config.enabled and config.get_effective_token():
            messages.success(request, 'SCIM settings saved successfully.')
        elif config.enabled:
            messages.warning(request, 'SCIM is enabled but no bearer token is set.')
        else:
            messages.info(request, 'SCIM endpoint is disabled.')
        return redirect('scim:settings')
