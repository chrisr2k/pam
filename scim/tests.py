"""Tests for the SCIM v2 endpoint."""

import json

from django.contrib.auth import get_user_model
from django.test import Client, TestCase, override_settings
from django.urls import reverse

from audit.models import AuditLog
from .models import ScimConfig

User = get_user_model()

TOKEN = 'test-token'


class ScimAuthTests(TestCase):
    """Bearer authentication."""

    def setUp(self):
        ScimConfig.objects.all().delete()
        self.config = ScimConfig.get_config()
        self.config.enabled = True
        self.config.set_bearer_token(TOKEN)
        self.config.save()

    def _get(self, path='/scim/v2/Users', headers=None):
        return Client().get(path, HTTP_HOST='localhost', **(headers or {}))

    def test_missing_token_401_with_www_authenticate(self):
        response = self._get()
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response['WWW-Authenticate'], 'Bearer')

    def test_wrong_token_401(self):
        response = self._get(headers={'HTTP_AUTHORIZATION': 'Bearer wrong'})
        self.assertEqual(response.status_code, 401)

    def test_disabled_config_401(self):
        self.config.enabled = False
        self.config.save()
        response = self._get(headers={'HTTP_AUTHORIZATION': f'Bearer {TOKEN}'})
        self.assertEqual(response.status_code, 401)

    def test_no_token_configured_401(self):
        self.config.set_bearer_token('')
        self.config.save()
        response = self._get(headers={'HTTP_AUTHORIZATION': 'Bearer anything'})
        self.assertEqual(response.status_code, 401)

    @override_settings(SCIM_BEARER_TOKEN='env-token')
    def test_env_fallback_token_accepted(self):
        self.config.set_bearer_token('')
        self.config.save()
        response = self._get(headers={'HTTP_AUTHORIZATION': 'Bearer env-token'})
        self.assertEqual(response.status_code, 200)

    def test_valid_token_passes(self):
        response = self._get(headers={'HTTP_AUTHORIZATION': f'Bearer {TOKEN}'})
        self.assertEqual(response.status_code, 200)


class ScimUserTests(TestCase):
    """User collection/resource endpoints."""

    def setUp(self):
        ScimConfig.objects.all().delete()
        self.config = ScimConfig.get_config()
        self.config.enabled = True
        self.config.set_bearer_token(TOKEN)
        self.config.save()
        self.auth = {'HTTP_AUTHORIZATION': f'Bearer {TOKEN}', 'HTTP_HOST': 'localhost'}
        self.alice = User.objects.create_user(
            username='alice', email='alice@contoso.com',
            first_name='Alice', last_name='Anderson',
            entra_object_id='oid-alice')

    def _request(self, method, path, data=None, extra=None):
        kwargs = dict(self.auth)
        if extra:
            kwargs.update(extra)
        if data is not None:
            kwargs['data'] = json.dumps(data)
            kwargs['content_type'] = 'application/scim+json'
        return Client().generic(method, path, **kwargs)

    def test_list_shape(self):
        response = self._request('GET', '/scim/v2/Users')
        body = response.json()
        self.assertEqual(body['totalResults'], 1)
        self.assertEqual(body['startIndex'], 1)
        self.assertEqual(len(body['Resources']), 1)
        self.assertEqual(body['Resources'][0]['userName'], 'alice')

    def test_filter_username_case_insensitive(self):
        response = self._request('GET', '/scim/v2/Users?filter=userName%20eq%20%22ALICE%22')
        self.assertEqual(response.json()['totalResults'], 1)

    def test_filter_externalid(self):
        response = self._request('GET', '/scim/v2/Users?filter=externalId%20eq%20%22oid-alice%22')
        self.assertEqual(response.json()['totalResults'], 1)

    def test_invalid_filter_400(self):
        response = self._request('GET', '/scim/v2/Users?filter=emails%20eq%20%22x%22')
        self.assertEqual(response.status_code, 400)
        self.assertIn('Error', response.json()['schemas'][0])

    def test_get_by_pk_and_externalid(self):
        self.assertEqual(self._request('GET', f'/scim/v2/Users/{self.alice.pk}').status_code, 200)
        self.assertEqual(
            self._request('GET', '/scim/v2/Users/oid-alice').status_code, 200)

    def test_unknown_id_404(self):
        response = self._request('GET', '/scim/v2/Users/999999')
        self.assertEqual(response.status_code, 404)
        self.assertIn('Error', response.json()['schemas'][0])

    def test_create_201_and_fields(self):
        data = {
            'schemas': ['urn:ietf:params:scim:schemas:core:2.0:User'],
            'externalId': 'oid-bob',
            'userName': 'bob@contoso.com',
            'name': {'givenName': 'Bob', 'familyName': 'Brown'},
            'emails': [{'value': 'bob@contoso.com'}],
            'active': True,
        }
        response = self._request('POST', '/scim/v2/Users', data=data)
        self.assertEqual(response.status_code, 201)
        bob = User.objects.get(entra_object_id='oid-bob')
        self.assertEqual(bob.username, 'bob')
        self.assertEqual(bob.email, 'bob@contoso.com')
        self.assertTrue(AuditLog.objects.filter(action='SCIM_USER_PROVISIONED').exists())

    def test_create_retry_idempotent(self):
        data = {'externalId': 'oid-retry', 'userName': 'retry@x.com'}
        self.assertEqual(self._request('POST', '/scim/v2/Users', data=data).status_code, 201)
        response = self._request('POST', '/scim/v2/Users', data=data)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(User.objects.filter(entra_object_id='oid-retry').count(), 1)

    def test_missing_external_id_400(self):
        response = self._request('POST', '/scim/v2/Users', data={'userName': 'x@y.com'})
        self.assertEqual(response.status_code, 400)

    def test_duplicate_username_conflict_409(self):
        data = {'externalId': 'oid-other', 'userName': 'alice@other.com'}
        response = self._request('POST', '/scim/v2/Users', data=data)
        self.assertEqual(response.status_code, 409)
        self.assertIn('uniqueness', response.json()['scimType'])

    def test_create_updates_existing_user_attributes(self):
        data = {
            'externalId': 'oid-alice', 'userName': 'alice@contoso.com',
            'name': {'givenName': 'Alicia', 'familyName': 'Anderson'},
            'emails': [{'value': 'alice@contoso.com'}],
        }
        self.assertEqual(self._request('POST', '/scim/v2/Users', data=data).status_code, 200)
        self.alice.refresh_from_db()
        self.assertEqual(self.alice.first_name, 'Alicia')

    def test_patch_deactivate(self):
        data = {'schemas': ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
                'Operations': [{'op': 'Replace', 'path': 'active', 'value': False}]}
        response = self._request('PATCH', f'/scim/v2/Users/{self.alice.pk}', data=data)
        self.assertEqual(response.status_code, 204)
        self.alice.refresh_from_db()
        self.assertFalse(self.alice.is_active)
        self.assertTrue(AuditLog.objects.filter(action='SCIM_USER_UPDATED').exists())

    def test_patch_updates_names_email_username(self):
        data = {'Operations': [
            {'op': 'Replace', 'value': {
                'name': {'givenName': 'Aly', 'familyName': 'Anderson'},
                'emails': [{'value': 'aly@contoso.com'}],
                'userName': 'aly@contoso.com',
            }},
        ]}
        self._request('PATCH', f'/scim/v2/Users/{self.alice.pk}', data=data)
        self.alice.refresh_from_db()
        self.assertEqual(self.alice.first_name, 'Aly')
        self.assertEqual(self.alice.email, 'aly@contoso.com')
        self.assertEqual(self.alice.username, 'aly')

    def test_patch_ignores_unknown_attributes(self):
        data = {'Operations': [
            {'op': 'Replace', 'path': 'department', 'value': 'Engineering'},
            {'op': 'Replace', 'value': {'displayName': 'X'}},
        ]}
        response = self._request('PATCH', f'/scim/v2/Users/{self.alice.pk}', data=data)
        self.assertEqual(response.status_code, 204)

    def test_patch_remove_active(self):
        data = {'Operations': [{'op': 'remove', 'path': 'active'}]}
        self._request('PATCH', f'/scim/v2/Users/{self.alice.pk}', data=data)
        self.alice.refresh_from_db()
        self.assertFalse(self.alice.is_active)

    def test_put_full_replace(self):
        data = {'externalId': 'oid-alice', 'userName': 'alice2@contoso.com',
                'name': {'givenName': 'A', 'familyName': 'B'}, 'active': False}
        response = self._request('PUT', f'/scim/v2/Users/{self.alice.pk}', data=data)
        self.assertEqual(response.status_code, 200)
        self.alice.refresh_from_db()
        self.assertEqual(self.alice.username, 'alice2')
        self.assertFalse(self.alice.is_active)

    def test_put_externalid_mismatch_400(self):
        data = {'externalId': 'oid-other', 'userName': 'alice@contoso.com'}
        response = self._request('PUT', f'/scim/v2/Users/{self.alice.pk}', data=data)
        self.assertEqual(response.status_code, 400)

    def test_delete_soft_deactivates(self):
        response = self._request('DELETE', f'/scim/v2/Users/{self.alice.pk}')
        self.assertEqual(response.status_code, 204)
        self.alice.refresh_from_db()
        self.assertFalse(self.alice.is_active)
        self.assertTrue(User.objects.filter(pk=self.alice.pk).exists())
        self.assertEqual(AuditLog.objects.filter(
            action='SCIM_USER_DEPROVISIONED').count(), 1)

    def test_second_delete_no_duplicate_audit(self):
        self._request('DELETE', f'/scim/v2/Users/{self.alice.pk}')
        self._request('DELETE', f'/scim/v2/Users/{self.alice.pk}')
        self.assertEqual(AuditLog.objects.filter(
            action='SCIM_USER_DEPROVISIONED').count(), 1)


class ScimDiscoveryTests(TestCase):
    """Groups + discovery endpoints."""

    def setUp(self):
        ScimConfig.objects.all().delete()
        config = ScimConfig.get_config()
        config.enabled = True
        config.set_bearer_token(TOKEN)
        config.save()
        self.auth = {'HTTP_AUTHORIZATION': f'Bearer {TOKEN}', 'HTTP_HOST': 'localhost'}

    def test_groups_get_empty(self):
        response = Client().get('/scim/v2/Groups', **self.auth)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['totalResults'], 0)

    def test_groups_post_501(self):
        response = Client().post('/scim/v2/Groups', data='{}',
                                 content_type='application/json', **self.auth)
        self.assertEqual(response.status_code, 501)

    def test_service_provider_config_shape(self):
        response = Client().get('/scim/v2/ServiceProviderConfig', **self.auth)
        body = response.json()
        self.assertTrue(body['patch']['supported'])
        self.assertEqual(
            body['authenticationSchemes'][0]['type'], 'oauthbearertoken')

    def test_schemas_and_resource_types_200(self):
        self.assertEqual(Client().get('/scim/v2/Schemas', **self.auth).status_code, 200)
        self.assertEqual(Client().get('/scim/v2/ResourceTypes', **self.auth).status_code, 200)
        self.assertEqual(Client().get('/scim/v2/', **self.auth).status_code, 200)


class ScimCsrfAndSettingsTests(TestCase):
    """CSRF exemption + settings page."""

    def setUp(self):
        ScimConfig.objects.all().delete()
        self.config = ScimConfig.get_config()
        self.config.enabled = True
        self.config.set_bearer_token(TOKEN)
        self.config.save()
        self.staff = User.objects.create_user(
            username='staff', password='x', is_staff=True)
        self.requester = User.objects.create_user(username='req', password='x')

    def test_post_without_csrf_token_succeeds(self):
        client = Client(enforce_csrf_checks=True)
        response = client.post(
            '/scim/v2/Users',
            data=json.dumps({'externalId': 'oid-csrf', 'userName': 'csrf@x.com'}),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {TOKEN}',
            HTTP_HOST='localhost')
        self.assertEqual(response.status_code, 201)

    def test_settings_page_staff_only(self):
        self.client.force_login(self.requester)
        self.assertEqual(self.client.get(reverse('scim:settings')).status_code, 403)
        self.client.force_login(self.staff)
        self.assertEqual(self.client.get(reverse('scim:settings')).status_code, 200)

    def test_settings_blank_token_keeps_existing(self):
        self.client.force_login(self.staff)
        self.client.post(reverse('scim:settings'), {
            'enabled': 'on',
            'bearer_token': '',
        })
        self.config.refresh_from_db()
        self.assertEqual(self.config.get_bearer_token(), TOKEN)

    def test_settings_new_token_replaces(self):
        self.client.force_login(self.staff)
        self.client.post(reverse('scim:settings'), {
            'enabled': 'on',
            'bearer_token': 'fresh-token',
        })
        self.config.refresh_from_db()
        self.assertEqual(self.config.get_bearer_token(), 'fresh-token')
