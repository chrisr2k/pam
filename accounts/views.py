import logging
import os
import secrets
from urllib.parse import urlparse

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.mixins import LoginRequiredMixin, UserPassesTestMixin
from django.core import signing
from django.http import Http404
from django.shortcuts import redirect, render
from django.urls import reverse
from django.utils import timezone
from django.utils.http import url_has_allowed_host_and_scheme
from django.views import View
from django.views.generic import TemplateView
import msal
import pyotp

from audit.middleware import log_action
from .mfa import (
    consume_mfa_ticket,
    mfa_clear_failures,
    mfa_is_locked,
    mfa_lockout_remaining,
    mfa_record_failure,
    normalize_code,
    verify_totp,
)
from .models import EntraConfig, AWSConfig


logger = logging.getLogger(__name__)

# Labels for the generic MFA challenge page (specific labels are set by the
# views that issue the ticket)
ACTION_LABELS = {
    'create_request': 'Submit access request',
    'approve_request': 'Approve access request',
    'break_glass': 'Break-glass emergency access',
    'reveal_vault_secret': 'Reveal vault secret',
}


def render_mfa_challenge(request, action_label, target_id, hidden_post):
    """Render the MFA challenge page for a freshly-issued ticket.

    Form data is re-submitted as hidden inputs (never stashed server-side);
    the ticket and target_id are passed explicitly.
    """
    context = {
        'action_label': action_label,
        'ticket': request.session.get('mfa_ticket', ''),
        'target_id': target_id,
        'hidden_fields': [
            (k, v) for k, v in hidden_post.items()
            if k not in ('code', 'csrfmiddlewaretoken', 'ticket', 'target_id')
        ],
        'error': None,
        'locked': False,
        'lockout_seconds': 0,
        'attempts_remaining': max(
            0,
            settings.PAM_MFA_MAX_ATTEMPTS - int(request.session.get('mfa_failed_attempts', 0)),
        ),
    }
    return render(request, 'pam/mfa_challenge.html', context)


def build_redirect_uri(request, path='/accounts/callback/'):
    """Build the redirect URI, preferring EXTERNAL_URL if set (for ngrok/reverse proxies)."""
    external_url = os.getenv('EXTERNAL_URL', '')
    if external_url:
        return external_url.rstrip('/') + path
    return request.build_absolute_uri(path)


class LoginView(View):
    """Redirect to Entra ID OIDC login."""

    def _get_entra_config(self):
        """Get Entra config from env var/vault first, then fall back to database.

        Env var / vault secrets take precedence over database-stored config.
        This allows OCI Vault / AWS Secrets Manager to override stale DB values.
        """
        if all([settings.ENTRA_TENANT_ID, settings.ENTRA_CLIENT_ID, settings.ENTRA_CLIENT_SECRET]):
            return settings
        # Fall back to database config
        db_config = EntraConfig.get_config()
        if db_config.is_configured():
            return db_config
        return None

    def get(self, request):
        if request.user.is_authenticated:
            return redirect(settings.LOGIN_REDIRECT_URL)

        config = self._get_entra_config()

        if config is None:
            # Fallback to login page if not configured
            return render(request, 'pam/login.html', {
                'oidc_disabled': True,
            })

        # Get credentials from config source
        if hasattr(config, 'tenant_id'):  # Database model
            client_id = config.client_id
            client_secret = config.get_client_secret()
            tenant_id = config.tenant_id
            # Use EXTERNAL_URL if set (for ngrok), otherwise use DB redirect_uri or build from request
            external_url = os.getenv('EXTERNAL_URL', '')
            if external_url:
                redirect_uri = build_redirect_uri(request, '/accounts/callback/')
            else:
                redirect_uri = config.redirect_uri or build_redirect_uri(request, '/accounts/callback/')
        else:  # settings module
            client_id = settings.ENTRA_CLIENT_ID
            client_secret = settings.ENTRA_CLIENT_SECRET
            tenant_id = settings.ENTRA_TENANT_ID
            redirect_uri = build_redirect_uri(request, '/accounts/callback/')

        # Create MSAL app
        app = msal.ConfidentialClientApplication(
            client_id=client_id,
            client_credential=client_secret,
            authority=f'https://login.microsoftonline.com/{tenant_id}',
        )

        # Generate and store OIDC state for CSRF protection
        oidc_state = secrets.token_urlsafe(32)
        request.session['oidc_state'] = oidc_state

        # Generate authorization URL
        auth_url = app.get_authorization_request_url(
            scopes=settings.ENTRA_SCOPES,
            redirect_uri=redirect_uri,
            state=oidc_state,
        )

        return redirect(auth_url)


class OIDCCallbackView(View):
    """Handle OIDC callback from Entra ID."""

    def get(self, request):
        code = request.GET.get('code')
        error = request.GET.get('error')
        returned_state = request.GET.get('state', '')

        if error:
            logger.error(f'OIDC error from provider: {error}')
            return render(request, 'pam/login.html', {
                'error': f'Authentication failed: {error}',
            })

        if not code:
            return render(request, 'pam/login.html', {
                'error': 'No authorization code received.',
            })

        # Validate OIDC state to prevent CSRF on the callback
        stored_state = request.session.pop('oidc_state', None)
        if not stored_state or not returned_state:
            logger.warning('OIDC callback missing state parameter')
            return render(request, 'pam/login.html', {
                'error': 'Authentication failed: invalid state parameter.',
            })
        if not secrets.compare_digest(stored_state, returned_state):
            logger.warning('OIDC state mismatch - possible CSRF attack')
            return render(request, 'pam/login.html', {
                'error': 'Authentication failed: state validation error.',
            })

        user = authenticate(request, code=code)
        if user is not None:
            login(request, user)
            log_action(
                actor=user,
                action='LOGIN',
                target_type='User',
                target_id=user.pk,
                details={'method': 'oidc'},
                request=request,
            )
            # Use next URL from session (set before OIDC redirect), validate to prevent open redirect
            next_url = request.session.pop('oidc_next', settings.LOGIN_REDIRECT_URL)
            if not url_has_allowed_host_and_scheme(next_url, allowed_hosts=None):
                next_url = settings.LOGIN_REDIRECT_URL
            return redirect(next_url)
        else:
            return render(request, 'pam/login.html', {
                'error': 'Authentication failed. Could not validate your credentials.',
            })


class LocalLoginView(View):
    """Handle local username/password login (non-OIDC)."""

    def post(self, request):
        username = request.POST.get('username', '').strip()
        password = request.POST.get('password', '')
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            log_action(
                actor=user,
                action='LOGIN',
                target_type='User',
                target_id=user.pk,
                details={'method': 'local'},
                request=request,
            )
            next_url = request.POST.get('next', settings.LOGIN_REDIRECT_URL)
            if not url_has_allowed_host_and_scheme(next_url, allowed_hosts=None):
                next_url = settings.LOGIN_REDIRECT_URL
            return redirect(next_url)
        return render(request, 'pam/login.html', {
            'oidc_disabled': True,
            'error': 'Invalid username or password.',
        })


class LogoutView(View):
    """Log out the user and redirect to Entra ID logout or home."""

    def get(self, request):
        user = request.user
        config = EntraConfig.get_config()
        logout(request)
        if user.is_authenticated:
            log_action(
                actor=user,
                action='LOGOUT',
                target_type='User',
                target_id=user.pk,
                request=request,
            )
        tenant_id = config.tenant_id or settings.ENTRA_TENANT_ID
        if tenant_id:
            logout_url = (
                f'https://login.microsoftonline.com/{tenant_id}'
                f'/oauth2/v2.0/logout?post_logout_redirect_uri='
                f'{build_redirect_uri(request, "/")}'
            )
        else:
            logout_url = '/'
        return redirect(logout_url)


class ProfileView(LoginRequiredMixin, View):
    """View and manage user profile."""

    def get(self, request):
        return render(request, 'pam/profile.html', {
            'user': request.user,
        })


class EntraSetupView(LoginRequiredMixin, UserPassesTestMixin, View):
    """Admin page for configuring Entra ID with step-by-step instructions."""

    def test_func(self):
        return self.request.user.is_staff or self.request.user.is_admin_user

    def get(self, request):
        config = EntraConfig.get_config()
        # Detect PIM auth method
        from providers.credential_factory import EntraCredentialFactory
        factory = EntraCredentialFactory()
        pim_auth_method = factory._detect_environment()
        return render(request, 'pam/entra_setup.html', {
            'config': config,
            'is_configured': config.is_configured(),
            'pim_auth_method': pim_auth_method,
            'callback_url': build_redirect_uri(request, '/accounts/callback/'),
        })

    def post(self, request):
        config = EntraConfig.get_config()
        config.tenant_id = request.POST.get('tenant_id', '').strip()
        config.client_id = request.POST.get('client_id', '').strip()
        raw_secret = request.POST.get('client_secret', '').strip()
        if raw_secret:
            config.set_client_secret(raw_secret)
        # If no new secret provided, keep the existing encrypted one
        config.redirect_uri = request.POST.get('redirect_uri', '').strip()

        # PIM-specific fields
        config.pim_tenant_id = request.POST.get('pim_tenant_id', '').strip()
        config.pim_client_id = request.POST.get('pim_client_id', '').strip()
        raw_pim_secret = request.POST.get('pim_client_secret', '').strip()
        if raw_pim_secret:
            config.set_pim_client_secret(raw_pim_secret)

        config.configured_by = request.user
        config.save()

        if config.is_configured():
            messages.success(request, 'Entra ID configuration saved successfully!')
        else:
            messages.warning(request, 'Configuration saved but is incomplete. Fill in all fields to enable Entra ID login.')

        return redirect('accounts:entra_setup')


class AWSSetupView(LoginRequiredMixin, UserPassesTestMixin, View):
    """Admin page for configuring AWS Identity Center with step-by-step instructions."""

    def test_func(self):
        return self.request.user.is_staff or self.request.user.is_admin_user

    def get(self, request):
        config = AWSConfig.get_config()
        return render(request, 'pam/aws_setup.html', {
            'config': config,
            'is_configured': config.is_configured(),
            'auth_method': config.get_auth_method(),
        })

    def post(self, request):
        config = AWSConfig.get_config()
        config.sso_instance_arn = request.POST.get('sso_instance_arn', '').strip()
        config.region = request.POST.get('region', 'us-east-1').strip()
        config.role_arn = request.POST.get('role_arn', '').strip()
        config.role_session_name = request.POST.get('role_session_name', 'PAM-Session').strip()
        config.external_id = request.POST.get('external_id', '').strip()
        config.roles_anywhere_profile_arn = request.POST.get('roles_anywhere_profile_arn', '').strip()
        config.roles_anywhere_trust_arn = request.POST.get('roles_anywhere_trust_arn', '').strip()
        config.access_key_id = request.POST.get('access_key_id', '').strip()
        config.secret_access_key = request.POST.get('secret_access_key', '').strip()
        config.configured_by = request.user
        config.save()

        if config.is_configured():
            messages.success(request, 'AWS Identity Center configuration saved successfully!')
        else:
            messages.warning(request, 'Configuration saved but is incomplete. Fill in at least one auth method.')

        return redirect('accounts:aws_setup')


class MFASetupView(LoginRequiredMixin, View):
    """Enroll (or re-enroll) a TOTP authenticator for elevation-time MFA."""

    def _qr_svg(self, otpauth_uri):
        """Build an inline SVG QR code (pure-Python, no Pillow)."""
        import qrcode
        import qrcode.image.svg
        img = qrcode.make(
            otpauth_uri,
            image_factory=qrcode.image.svg.SvgPathImage,
            box_size=4,
            border=2,
        )
        svg = img.to_string()
        if isinstance(svg, bytes):
            svg = svg.decode('utf-8')
        return svg

    def get(self, request):
        user = request.user
        pending_secret = request.session.get('mfa_pending_secret', '')
        if not pending_secret:
            pending_secret = pyotp.random_base32()
            request.session['mfa_pending_secret'] = pending_secret
        otpauth_uri = pyotp.TOTP(pending_secret).provisioning_uri(
            name=user.email or user.username,
            issuer_name=settings.PAM_MFA_ISSUER,
        )
        return render(request, 'pam/mfa_setup.html', {
            'user': user,
            'secret': pending_secret,
            'otpauth_uri': otpauth_uri,
            'qr_svg': self._qr_svg(otpauth_uri),
            'required': user.mfa_required,
        })

    def post(self, request):
        user = request.user
        pending_secret = request.session.get('mfa_pending_secret', '')
        code = normalize_code(request.POST.get('code', ''))
        if not pending_secret:
            messages.error(request, 'No pending MFA setup found. Please try again.')
            return redirect('accounts:mfa_setup')
        # Verify against the pending secret; a failed attempt keeps it in the
        # session so the page can be refreshed without generating a new one.
        if not pyotp.TOTP(pending_secret).verify(code, valid_window=1):
            messages.error(request, 'Invalid verification code. Please try again.')
            return redirect('accounts:mfa_setup')
        was_enrolled = user.mfa_enrolled
        user.set_otp_secret(pending_secret)
        user.mfa_enrolled_at = timezone.now()
        user.save(update_fields=['otp_secret', 'mfa_enrolled_at'])
        request.session.pop('mfa_pending_secret', None)
        log_action(
            actor=user,
            action='MFA_ENROLLED',
            target_type='User',
            target_id=user.pk,
            details={'re_enroll': was_enrolled},
            request=request,
        )
        if was_enrolled:
            messages.success(request, 'MFA secret replaced successfully.')
        else:
            messages.success(request, 'MFA enrolled successfully.')
        return redirect('accounts:profile')


class MFARemoveView(LoginRequiredMixin, View):
    """Remove MFA enrollment (blocked for roles that require MFA)."""

    def post(self, request):
        user = request.user
        if user.mfa_required:
            messages.error(request, 'MFA is required for your role and cannot be removed.')
            return redirect('accounts:profile')
        if not user.mfa_enrolled:
            messages.warning(request, 'MFA is not enrolled.')
            return redirect('accounts:profile')
        code = request.POST.get('code', '').strip()
        if not verify_totp(user, code):
            messages.error(request, 'Invalid verification code.')
            return redirect('accounts:profile')
        user.set_otp_secret('')
        user.mfa_enrolled_at = None
        user.save(update_fields=['otp_secret', 'mfa_enrolled_at'])
        log_action(
            actor=user,
            action='MFA_REMOVED',
            target_type='User',
            target_id=user.pk,
            request=request,
        )
        messages.success(request, 'MFA removed.')
        return redirect('accounts:profile')


class MFAChallengeView(LoginRequiredMixin, View):
    """Verify a TOTP code for a ticketed action (submit/approve/break-glass)."""

    def _decode_session_ticket(self, request):
        """Best-effort decode of the session ticket for display context."""
        ticket = request.session.get('mfa_ticket', '')
        if not ticket:
            return None
        try:
            return signing.loads(ticket, salt='pam.mfa_ticket', max_age=settings.PAM_MFA_TICKET_TTL)
        except (signing.SignatureExpired, signing.BadSignature):
            return None

    def _challenge_context(self, request, payload, hidden_post, error=None):
        action = payload.get('action', '') if payload else ''
        return {
            'action_label': ACTION_LABELS.get(action, 'Verify your identity'),
            'ticket': request.session.get('mfa_ticket', ''),
            'target_id': (payload or {}).get('target_id', ''),
            'hidden_fields': [
                (k, v) for k, v in hidden_post.items()
                if k not in ('code', 'csrfmiddlewaretoken', 'ticket', 'target_id')
            ],
            'error': error,
            'locked': mfa_is_locked(request),
            'lockout_seconds': mfa_lockout_remaining(request),
            'attempts_remaining': max(
                0,
                settings.PAM_MFA_MAX_ATTEMPTS - int(request.session.get('mfa_failed_attempts', 0)),
            ),
        }

    def _render_error(self, request, payload, hidden_post, error):
        return render(request, 'pam/mfa_challenge.html',
                      self._challenge_context(request, payload, hidden_post, error=error))

    def get(self, request):
        # Direct navigation / refresh: the ticket survives in the session but
        # action-specific form data does not. Approve can still be completed
        # (comment is optional); other actions will fail re-validation on POST.
        payload = self._decode_session_ticket(request)
        if payload is None or payload.get('user_id') != str(request.user.pk):
            messages.error(request, 'No pending action to verify.')
            return redirect('requests:dashboard')
        context = self._challenge_context(request, payload, {})
        context['refreshed'] = True
        return render(request, 'pam/mfa_challenge.html', context)

    def post(self, request):
        code = request.POST.get('code', '').strip()
        ticket_submitted = request.POST.get('ticket', '')
        target_id = request.POST.get('target_id', '')
        hidden_post = request.POST
        payload = self._decode_session_ticket(request)

        if mfa_is_locked(request):
            return self._render_error(
                request, payload, hidden_post,
                'Too many failed attempts. Please wait before retrying.',
            )

        payload, error = consume_mfa_ticket(request, ticket_submitted, target_id)
        if error:
            # Make pre-verification failures observable (they previously left
            # no trace in the audit trail)
            log_action(
                actor=request.user,
                action='MFA_CHALLENGE_FAILED',
                target_type='User',
                target_id=request.user.pk,
                details={
                    'action': payload.get('action') if payload else 'unknown',
                    'reason': error,
                },
                request=request,
            )
            return self._render_error(request, payload, hidden_post, error)

        if not verify_totp(request.user, code):
            locked = mfa_record_failure(request)
            log_action(
                actor=request.user,
                action='MFA_CHALLENGE_FAILED',
                target_type='User',
                target_id=request.user.pk,
                details={'action': payload['action'], 'locked': locked},
                request=request,
            )
            error = (
                f'Too many failed attempts. MFA challenge locked for '
                f'{settings.PAM_MFA_LOCKOUT_MINUTES} minutes.'
                if locked else 'Invalid verification code.'
            )
            return self._render_error(request, payload, hidden_post, error)

        # Success: the ticket is single-use, reset counters, rotate the
        # session key to prevent fixation. Session rotation is a hardening
        # nicety — if it fails, log it and continue rather than failing the
        # user's approved action.
        request.session.pop('mfa_ticket', None)
        mfa_clear_failures(request)
        try:
            request.session.cycle_key()
        except Exception:
            logger.exception('Session cycle failed after MFA challenge (continuing)')

        from access_requests import services as ar_services
        action = payload['action']
        if action == 'approve_request':
            ok, err, outcome = ar_services.execute_approve(
                request.user, target_id,
                comment=request.POST.get('comment', ''),
                request=request)
            if not ok:
                return self._render_error(request, payload, hidden_post, err)
            if outcome == 'vote_recorded':
                messages.success(
                    request,
                    'Your approval has been recorded. Additional approvals are '
                    'needed before access is granted.',
                )
            elif outcome == 'duplicate_vote':
                messages.info(request, 'You have already approved this request.')
            else:
                messages.success(request, f'Request #{target_id} approved.')
            return redirect('requests:detail', pk=target_id)
        if action == 'create_request':
            access_request, form = ar_services.execute_create(
                request.user, request.POST, request=request)
            if access_request is None:
                err = ('Request data was lost or invalid. '
                       'Please submit the request again from the request form.')
                if form is not None and form.errors:
                    err = 'Invalid request data: ' + '; '.join(
                        f'{field}: {", ".join(msgs)}' for field, msgs in form.errors.items())
                return self._render_error(request, payload, hidden_post, err)
            if ar_services.duration_was_clamped(request.POST, access_request):
                messages.warning(
                    request,
                    f'Requested duration exceeds the '
                    f'{access_request.role.max_duration_minutes}-minute maximum '
                    f'for this role and was reduced.',
                )
            if access_request.status == access_request.Status.APPROVED:
                messages.success(
                    request,
                    'Access granted automatically — this role does not require approval.',
                )
            else:
                messages.success(request, 'Access request submitted successfully.')
            return redirect('requests:detail', pk=access_request.pk)
        if action == 'break_glass':
            access_request, err = ar_services.execute_break_glass(
                request.user, target_id,
                justification=request.POST.get('justification', ''),
                duration_minutes=request.POST.get('duration_minutes', ''))
            if access_request is None:
                return self._render_error(request, payload, hidden_post, err)
            return redirect('requests:detail', pk=access_request.pk)
        if action == 'reveal_vault_secret':
            from vault import services as vault_services
            secret, err = vault_services.execute_reveal(
                request.user, int(target_id), request=request)
            if err:
                return self._render_error(request, payload, hidden_post, err)
            messages.success(
                request,
                f'Secret revealed: {secret} — copy it now; it is shown only once.',
            )
            return redirect('vault:detail', pk=int(target_id))

        messages.error(request, 'Unknown challenge action.')
        return redirect('requests:dashboard')


class HelpView(LoginRequiredMixin, TemplateView):
    """In-app user guide pages."""

    HELP_SECTIONS = {
        'overview': 'pam/help/overview.html',
        'requests': 'pam/help/requests.html',
        'mfa': 'pam/help/mfa.html',
        'vault': 'pam/help/vault.html',
        'admin': 'pam/help/admin.html',
    }
    template_name = 'pam/help/overview.html'

    def get_template_names(self):
        section = self.kwargs.get('section', 'overview')
        if section not in self.HELP_SECTIONS:
            raise Http404('Unknown help section')
        return [self.HELP_SECTIONS[section]]

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['sections'] = [
            ('overview', 'Getting Started'),
            ('requests', 'Requests & Approvals'),
            ('mfa', 'Multi-Factor Auth'),
            ('vault', 'The Vault'),
            ('admin', 'For Administrators'),
        ]
        context['active_section'] = self.kwargs.get('section', 'overview')
        return context


