import logging
from django.conf import settings
from django.contrib.auth.backends import BaseBackend
from django.contrib.auth import get_user_model
import msal
import requests

from .models import EntraConfig

logger = logging.getLogger(__name__)

User = get_user_model()


class EntraOIDCBackend(BaseBackend):
    """
    Authentication backend for Entra ID (Azure AD) OIDC.
    Validates the ID token and creates/updates the local user.
    """

    def _get_entra_credentials(self):
        """Get Entra credentials by merging env var/vault values with database config.

        Env var / vault secrets take precedence over database-stored config.
        This allows OCI Vault / AWS Secrets Manager to override stale DB values
        even when ENTRA_TENANT_ID and ENTRA_CLIENT_ID are stored in the database.

        The three values (tenant_id, client_id, client_secret) are merged:
          1. Prefer settings (env var / cloud vault) for each field
          2. Fall back to database EntraConfig for any field not set in env
        """
        db_config = EntraConfig.get_config()

        creds = {
            'tenant_id': settings.ENTRA_TENANT_ID or db_config.tenant_id,
            'client_id': settings.ENTRA_CLIENT_ID or db_config.client_id,
            'client_secret': settings.ENTRA_CLIENT_SECRET or db_config.get_client_secret(),
        }

        if all(creds.values()):
            return creds

        return None

    def authenticate(self, request, code=None, **kwargs):
        """Exchange authorization code for tokens and authenticate user."""
        if not code:
            return None

        creds = self._get_entra_credentials()
        if not creds:
            logger.error('Entra ID OIDC not configured')
            return None

        tenant_id = creds['tenant_id']
        client_id = creds['client_id']
        client_secret = creds['client_secret']

        try:
            # Create MSAL confidential client
            authority = f'https://login.microsoftonline.com/{tenant_id}'
            app = msal.ConfidentialClientApplication(
                client_id=client_id,
                client_credential=client_secret,
                authority=authority,
            )

            # Get the redirect URI from the request
            redirect_uri = request.build_absolute_uri('/accounts/callback/')

            # Exchange code for token
            result = app.acquire_token_by_authorization_code(
                code=code,
                scopes=settings.ENTRA_SCOPES,
                redirect_uri=redirect_uri,
            )

            if 'error' in result:
                logger.error(f'OIDC token error: {result.get("error_description", result["error"])}')
                return None

            id_token = result.get('id_token_claims', {})
            if not id_token:
                logger.error('No ID token claims in result')
                return None

            # Extract user info from ID token
            entra_oid = id_token.get('oid') or id_token.get('sub')
            email = id_token.get('email') or id_token.get('preferred_username', '')
            given_name = id_token.get('given_name', '')
            family_name = id_token.get('family_name', '')
            username = (id_token.get('preferred_username', email) or email).split('@')[0]

            if not entra_oid:
                logger.error('No object ID in token')
                return None

            # Get or create user
            user, created = User.objects.get_or_create(
                entra_object_id=entra_oid,
                defaults={
                    'username': username,
                    'email': email,
                    'first_name': given_name,
                    'last_name': family_name,
                },
            )

            if not created:
                # Update user info
                updated = False
                if email and user.email != email:
                    user.email = email
                    updated = True
                if given_name and user.first_name != given_name:
                    user.first_name = given_name
                    updated = True
                if family_name and user.last_name != family_name:
                    user.last_name = family_name
                    updated = True
                if updated:
                    user.save()

            # Store access token in session for Graph API calls
            if 'access_token' in result:
                request.session['entra_access_token'] = result['access_token']

            return user

        except Exception as e:
            logger.exception(f'OIDC authentication error: {e}')
            return None

    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None
