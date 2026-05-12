"""Tests for the accounts app - models, views, backends, and OIDC flow."""

import os
from unittest.mock import patch, MagicMock, PropertyMock
from django.test import TestCase, RequestFactory, override_settings
from django.contrib.auth import get_user_model
from django.urls import reverse
from django.conf import settings
from django.contrib.messages import get_messages
import secrets

from .models import EntraConfig
from .backends import EntraOIDCBackend
from .views import build_redirect_uri

User = get_user_model()


class UserModelTests(TestCase):
    """Test the custom User model."""

    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123',
            first_name='Test',
            last_name='User',
        )

    def test_user_creation(self):
        """Test basic user creation."""
        self.assertEqual(self.user.username, 'testuser')
        self.assertEqual(self.user.email, 'test@example.com')
        self.assertEqual(self.user.role, User.Role.REQUESTER)

    def test_user_str(self):
        """Test string representation."""
        self.assertIn('Test User', str(self.user))
        self.assertIn('Requester', str(self.user))

    def test_is_approver_requester(self):
        """Test that a REQUESTER is not an approver."""
        self.assertFalse(self.user.is_approver)

    def test_is_approver_approver(self):
        """Test that an APPROVER is an approver."""
        self.user.role = User.Role.APPROVER
        self.assertTrue(self.user.is_approver)

    def test_is_approver_admin(self):
        """Test that an ADMIN is an approver."""
        self.user.role = User.Role.ADMIN
        self.assertTrue(self.user.is_approver)

    def test_is_admin_user(self):
        """Test admin role check."""
        self.assertFalse(self.user.is_admin_user)
        self.user.role = User.Role.ADMIN
        self.assertTrue(self.user.is_admin_user)

    def test_is_auditor(self):
        """Test auditor role check."""
        self.assertFalse(self.user.is_auditor)
        self.user.role = User.Role.AUDITOR
        self.assertTrue(self.user.is_auditor)

    def test_entra_object_id_unique(self):
        """Test that entra_object_id must be unique."""
        self.user.entra_object_id = 'abc-123'
        self.user.save()
        user2 = User.objects.create_user(
            username='testuser2',
            email='test2@example.com',
        )
        user2.entra_object_id = 'abc-123'
        with self.assertRaises(Exception):
            user2.save()

    def test_manager_relationship(self):
        """Test manager foreign key."""
        manager = User.objects.create_user(
            username='manager',
            email='manager@example.com',
            role=User.Role.APPROVER,
        )
        self.user.manager = manager
        self.user.save()
        self.assertEqual(self.user.manager, manager)
        self.assertIn(self.user, manager.direct_reports.all())


class EntraConfigModelTests(TestCase):
    """Test the EntraConfig singleton model."""

    def setUp(self):
        # Clear any existing config
        EntraConfig.objects.all().delete()

    def test_get_config_creates_default(self):
        """Test get_config creates a default config if none exists."""
        config = EntraConfig.get_config()
        self.assertIsNotNone(config)
        self.assertEqual(config.pk, 1)
        self.assertEqual(config.tenant_id, '')
        self.assertEqual(config.client_id, '')
        self.assertEqual(config.client_secret, '')

    def test_get_config_returns_existing(self):
        """Test get_config returns existing config."""
        config1 = EntraConfig.get_config()
        config2 = EntraConfig.get_config()
        self.assertEqual(config1.pk, config2.pk)

    def test_is_configured_empty(self):
        """Test is_configured returns False when empty."""
        config = EntraConfig.get_config()
        self.assertFalse(config.is_configured())

    def test_is_configured_complete(self):
        """Test is_configured returns True when all fields set."""
        config = EntraConfig.get_config()
        config.tenant_id = 'tenant-123'
        config.client_id = 'client-456'
        config.client_secret = 'secret-789'
        self.assertTrue(config.is_configured())

    def test_is_configured_partial(self):
        """Test is_configured returns False when partially set."""
        config = EntraConfig.get_config()
        config.tenant_id = 'tenant-123'
        config.client_id = 'client-456'
        # No client_secret
        self.assertFalse(config.is_configured())

    def test_save_always_pk_1(self):
        """Test that save always forces pk=1 (singleton)."""
        config = EntraConfig.get_config()
        config.pk = 999
        config.save()
        self.assertEqual(config.pk, 1)

    def test_str_not_configured(self):
        """Test string representation when not configured."""
        config = EntraConfig.get_config()
        self.assertIn('Not configured', str(config))

    def test_str_configured(self):
        """Test string representation when configured."""
        config = EntraConfig.get_config()
        config.tenant_id = 'my-tenant'
        self.assertIn('my-tenant', str(config))


class BuildRedirectUriTests(TestCase):
    """Test the build_redirect_uri helper function."""

    @patch.dict(os.environ, {'EXTERNAL_URL': ''}, clear=True)
    def test_build_from_request(self):
        """Test building redirect URI from request."""
        request = self.client.get('/accounts/login/').wsgi_request
        uri = build_redirect_uri(request, '/accounts/callback/')
        self.assertIn('/accounts/callback/', uri)

    @patch.dict(os.environ, {'EXTERNAL_URL': ''}, clear=True)
    def test_build_from_request_custom_path(self):
        """Test building redirect URI with custom path."""
        request = self.client.get('/accounts/login/').wsgi_request
        uri = build_redirect_uri(request, '/custom/path/')
        self.assertIn('/custom/path/', uri)


class LoginViewTests(TestCase):
    """Test the LoginView."""

    def setUp(self):
        self.factory = RequestFactory()
        self.login_url = reverse('accounts:login')

    def test_redirect_if_authenticated(self):
        """Test that authenticated users are redirected."""
        user = User.objects.create_user(username='testuser', password='testpass')
        self.client.force_login(user)
        response = self.client.get(self.login_url)
        self.assertRedirects(response, reverse('requests:dashboard'))

    def test_login_page_without_config(self):
        """Test login page shows disabled message when no config."""
        EntraConfig.objects.all().delete()
        response = self.client.get(self.login_url)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'pam/login.html')
        self.assertTrue(response.context.get('oidc_disabled'))

    @patch('accounts.views.msal.ConfidentialClientApplication')
    def test_login_page_with_db_config(self, mock_msal_app):
        """Test login page redirects to Entra when DB config exists."""
        mock_instance = MagicMock()
        mock_instance.get_authorization_request_url.return_value = (
            'https://login.microsoftonline.com/test-tenant/oauth2/v2.0/authorize?client_id=test-client'
        )
        mock_msal_app.return_value = mock_instance

        config = EntraConfig.get_config()
        config.tenant_id = 'test-tenant'
        config.client_id = 'test-client'
        config.client_secret = 'test-secret'
        config.save()
        response = self.client.get(self.login_url)
        # Should redirect to Microsoft login
        self.assertEqual(response.status_code, 302)
        self.assertIn('login.microsoftonline.com', response.url)

    @patch('accounts.views.msal.ConfidentialClientApplication')
    def test_login_stores_oidc_state(self, mock_msal_app):
        """Test that OIDC state is stored in session."""
        mock_instance = MagicMock()
        mock_instance.get_authorization_request_url.return_value = (
            'https://login.microsoftonline.com/test-tenant/oauth2/v2.0/authorize'
        )
        mock_msal_app.return_value = mock_instance

        config = EntraConfig.get_config()
        config.tenant_id = 'test-tenant'
        config.client_id = 'test-client'
        config.client_secret = 'test-secret'
        config.save()
        self.client.get(self.login_url)
        self.assertIn('oidc_state', self.client.session)


class OIDCCallbackViewTests(TestCase):
    """Test the OIDC callback view."""

    def setUp(self):
        self.callback_url = reverse('accounts:callback')

    def test_callback_with_error(self):
        """Test callback with error parameter."""
        response = self.client.get(self.callback_url, {'error': 'access_denied'})
        self.assertEqual(response.status_code, 200)
        self.assertIn('access_denied', response.content.decode())

    def test_callback_without_code(self):
        """Test callback without authorization code."""
        response = self.client.get(self.callback_url)
        self.assertEqual(response.status_code, 200)
        self.assertIn('No authorization code', response.content.decode())

    def test_callback_missing_state(self):
        """Test callback with missing state (CSRF protection)."""
        response = self.client.get(self.callback_url, {'code': 'some-code'})
        self.assertEqual(response.status_code, 200)
        self.assertIn('invalid state', response.content.decode())

    def test_callback_state_mismatch(self):
        """Test callback with mismatched state (CSRF attack)."""
        session = self.client.session
        session['oidc_state'] = 'real-state'
        session.save()
        response = self.client.get(self.callback_url, {
            'code': 'some-code',
            'state': 'fake-state',
        })
        self.assertEqual(response.status_code, 200)
        self.assertIn('state validation error', response.content.decode())


class EntraSetupViewTests(TestCase):
    """Test the Entra setup view."""

    def setUp(self):
        self.setup_url = reverse('accounts:entra_setup')
        self.admin_user = User.objects.create_superuser(
            username='admin',
            email='admin@example.com',
            password='adminpass',
        )

    def test_setup_requires_login(self):
        """Test that setup page requires authentication."""
        response = self.client.get(self.setup_url)
        self.assertEqual(response.status_code, 302)

    def test_setup_requires_admin(self):
        """Test that setup page requires admin."""
        user = User.objects.create_user(username='regular', password='testpass')
        self.client.force_login(user)
        response = self.client.get(self.setup_url)
        self.assertEqual(response.status_code, 403)

    def test_setup_page_loads(self):
        """Test that setup page loads for admin."""
        self.client.force_login(self.admin_user)
        response = self.client.get(self.setup_url)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'pam/entra_setup.html')

    def test_setup_post_saves_config(self):
        """Test that POST saves Entra config."""
        self.client.force_login(self.admin_user)
        response = self.client.post(self.setup_url, {
            'tenant_id': 'new-tenant',
            'client_id': 'new-client',
            'client_secret': 'new-secret',
            'redirect_uri': 'http://localhost:8080/callback/',
        })
        self.assertRedirects(response, self.setup_url)
        config = EntraConfig.get_config()
        self.assertEqual(config.tenant_id, 'new-tenant')
        self.assertEqual(config.client_id, 'new-client')
        self.assertEqual(config.client_secret, 'new-secret')

    def test_setup_post_success_message(self):
        """Test that successful POST shows success message."""
        self.client.force_login(self.admin_user)
        response = self.client.post(self.setup_url, {
            'tenant_id': 't', 'client_id': 'c', 'client_secret': 's',
        }, follow=True)
        messages = list(get_messages(response.wsgi_request))
        self.assertTrue(any('successfully' in str(m) for m in messages))

    def test_setup_post_incomplete_message(self):
        """Test that incomplete POST shows warning."""
        self.client.force_login(self.admin_user)
        response = self.client.post(self.setup_url, {
            'tenant_id': 't', 'client_id': '', 'client_secret': '',
        }, follow=True)
        messages = list(get_messages(response.wsgi_request))
        self.assertTrue(any('incomplete' in str(m).lower() for m in messages))


class EntraOIDCBackendTests(TestCase):
    """Test the Entra OIDC authentication backend."""

    def setUp(self):
        self.backend = EntraOIDCBackend()
        self.user = User.objects.create_user(
            username='testuser@example.com',
            email='testuser@example.com',
        )

    def test_get_user_exists(self):
        """Test get_user returns existing user."""
        result = self.backend.get_user(self.user.pk)
        self.assertEqual(result, self.user)

    def test_get_user_not_found(self):
        """Test get_user returns None for non-existent user."""
        result = self.backend.get_user(99999)
        self.assertIsNone(result)

    @patch('accounts.backends.EntraOIDCBackend._get_entra_credentials')
    @patch('accounts.backends.msal.ConfidentialClientApplication')
    def test_authenticate_new_user(self, mock_msal_app, mock_get_creds):
        """Test authenticating a new user creates account."""
        mock_get_creds.return_value = {
            'tenant_id': 'test-tenant',
            'client_id': 'test-client',
            'client_secret': 'test-secret',
        }
        mock_app_instance = MagicMock()
        mock_msal_app.return_value = mock_app_instance
        mock_app_instance.acquire_token_by_authorization_code.return_value = {
            'id_token_claims': {
                'preferred_username': 'newuser@example.com',
                'given_name': 'New',
                'family_name': 'User',
                'email': 'newuser@example.com',
                'oid': 'oid-12345',
            }
        }

        request = MagicMock()
        request.build_absolute_uri.return_value = 'http://localhost:8080/accounts/callback/'

        user = self.backend.authenticate(request=request, code='test-code')
        self.assertIsNotNone(user)
        # Backend splits username on @ and takes first part
        self.assertEqual(user.username, 'newuser')
        self.assertEqual(user.entra_object_id, 'oid-12345')
        self.assertEqual(user.first_name, 'New')
        self.assertEqual(user.last_name, 'User')

    @patch('accounts.backends.EntraOIDCBackend._get_entra_credentials')
    @patch('accounts.backends.msal.ConfidentialClientApplication')
    def test_authenticate_existing_user(self, mock_msal_app, mock_get_creds):
        """Test authenticating an existing user updates their info."""
        mock_get_creds.return_value = {
            'tenant_id': 'test-tenant',
            'client_id': 'test-client',
            'client_secret': 'test-secret',
        }
        mock_app_instance = MagicMock()
        mock_msal_app.return_value = mock_app_instance
        mock_app_instance.acquire_token_by_authorization_code.return_value = {
            'id_token_claims': {
                'preferred_username': 'testuser@example.com',
                'given_name': 'Updated',
                'family_name': 'Name',
                'email': 'testuser@example.com',
                'oid': 'oid-67890',
            }
        }

        request = MagicMock()
        request.build_absolute_uri.return_value = 'http://localhost:8080/accounts/callback/'

        user = self.backend.authenticate(request=request, code='test-code')
        self.assertIsNotNone(user)
        self.assertEqual(user.entra_object_id, 'oid-67890')
        # Refresh from DB
        user.refresh_from_db()
        self.assertEqual(user.first_name, 'Updated')

    @patch('accounts.backends.EntraOIDCBackend._get_entra_credentials')
    def test_authenticate_token_failure(self, mock_get_creds):
        """Test authentication fails when credentials are missing."""
        mock_get_creds.return_value = None
        user = self.backend.authenticate(request=None, code='bad-code')
        self.assertIsNone(user)


class ProfileViewTests(TestCase):
    """Test the profile view."""

    def setUp(self):
        self.profile_url = reverse('accounts:profile')
        self.user = User.objects.create_user(
            username='testuser',
            password='testpass',
            first_name='Test',
            last_name='User',
        )

    def test_profile_requires_login(self):
        """Test that profile requires authentication."""
        response = self.client.get(self.profile_url)
        self.assertEqual(response.status_code, 302)

    def test_profile_shows_user_info(self):
        """Test that profile shows user information."""
        self.client.force_login(self.user)
        response = self.client.get(self.profile_url)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'pam/profile.html')
        self.assertEqual(response.context['user'], self.user)


class LogoutViewTests(TestCase):
    """Test the logout view."""

    def setUp(self):
        self.logout_url = reverse('accounts:logout')
        self.user = User.objects.create_user(username='testuser', password='testpass')

    def test_logout_redirects(self):
        """Test that logout redirects to Microsoft logout."""
        self.client.force_login(self.user)
        response = self.client.get(self.logout_url)
        self.assertEqual(response.status_code, 302)
        self.assertIn('login.microsoftonline.com', response.url)
        self.assertIn('logout', response.url)
