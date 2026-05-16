import logging
import os
import secrets
from urllib.parse import urlparse

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.mixins import LoginRequiredMixin, UserPassesTestMixin
from django.shortcuts import redirect, render
from django.urls import reverse
from django.utils.http import url_has_allowed_host_and_scheme
from django.views import View
import msal

from .models import EntraConfig

logger = logging.getLogger(__name__)


def build_redirect_uri(request, path='/accounts/callback/'):
    """Build the redirect URI, preferring EXTERNAL_URL if set (for ngrok/reverse proxies)."""
    external_url = os.getenv('EXTERNAL_URL', '')
    if external_url:
        return external_url.rstrip('/') + path
    return request.build_absolute_uri(path)


class LoginView(View):
    """Redirect to Entra ID OIDC login."""

    def _get_entra_config(self):
        """Get Entra config from database or fall back to settings."""
        db_config = EntraConfig.get_config()
        if db_config.is_configured():
            return db_config
        # Fall back to settings from .env
        if all([settings.ENTRA_TENANT_ID, settings.ENTRA_CLIENT_ID, settings.ENTRA_CLIENT_SECRET]):
            return settings
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
            # Use next URL from session (set before OIDC redirect), validate to prevent open redirect
            next_url = request.session.pop('oidc_next', settings.LOGIN_REDIRECT_URL)
            if not url_has_allowed_host_and_scheme(next_url, allowed_hosts=None):
                next_url = settings.LOGIN_REDIRECT_URL
            return redirect(next_url)
        else:
            return render(request, 'pam/login.html', {
                'error': 'Authentication failed. Could not validate your credentials.',
            })


class LogoutView(View):
    """Log out the user and redirect to Entra ID logout."""

    def get(self, request):
        config = EntraConfig.get_config()
        logout(request)
        # Redirect to Entra ID logout endpoint
        logout_url = (
            f'https://login.microsoftonline.com/{config.tenant_id or settings.ENTRA_TENANT_ID}'
            f'/oauth2/v2.0/logout?post_logout_redirect_uri='
            f'{build_redirect_uri(request, "/")}'
        )
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
