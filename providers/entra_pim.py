"""
Entra ID PIM provider using Microsoft Graph API.

Uses the EntraCredentialFactory to auto-select the best authentication method:
- ManagedIdentityCredential (Azure environments)
- ClientCertificateCredential (non-Azure with certificate)
- ClientSecretCredential (development fallback)

Uses SEPARATE credentials from the OIDC login app for security isolation.
The PIM management app should have only the permissions it needs:
    - PrivilegedAccess.ReadWrite.AzureAD
    - RoleManagement.ReadWrite.Directory
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Optional

import httpx
from django.conf import settings
from django.contrib.auth import get_user_model

from .base import BasePrivilegedAccessProvider
from .credential_factory import EntraCredentialFactory

logger = logging.getLogger(__name__)

User = get_user_model()


class EntraPIMProvider(BasePrivilegedAccessProvider):
    """
    Provider implementation for Entra ID privileged access management.
    Uses Microsoft Graph API to assign/unassign directory roles directly.

    Authentication method is auto-selected by EntraCredentialFactory:
    - Azure: ManagedIdentityCredential (no secrets)
    - OCI/On-prem: ClientCertificateCredential (cert from vault or file)
    - Dev: ClientSecretCredential (fallback, not recommended for production)

    How it works:
    - Provision: Creates a permanent role assignment via adminAssign
    - Deprovision: Deletes the role assignment to remove access
    - The PAM app manages the timer and deprovisions automatically
    """

    GRAPH_API_BASE = 'https://graph.microsoft.com/v1.0'

    def __init__(self):
        self._access_token = None
        self._factory = EntraCredentialFactory()
        self._tenant_id = None
        self._client_id = None
        self._client_secret = None

    def _load_config(self):
        """Load PIM-specific Entra config from vault/env first, then DB.

        Precedence (highest to lowest):
        1. Cloud vault secrets (OCI Vault / AWS Secrets Manager / Azure Key Vault)
        2. Environment variables
        3. Database-stored config
        4. OIDC app credentials (fallback)

        IMPORTANT: The PIM client_id MUST be resolved BEFORE detecting the
        credential environment, because the certificate is registered on the
        PIM app, not the OIDC login app.
        """
        if self._client_id and self._tenant_id:
            return

        # Step 1: Resolve the PIM tenant_id and client_id from all sources
        from pam.secrets_resolver import get_secret
        vault_pim_secret = get_secret('ENTRA_PIM_CLIENT_SECRET', '')
        vault_pim_cert_b64 = get_secret('ENTRA_PIM_CERTIFICATE_B64', '')
        vault_pim_cert_password = get_secret('ENTRA_PIM_CERTIFICATE_PASSWORD', '')

        # Resolve tenant_id (try PIM-specific first, then main)
        pim_tenant = (
            settings.ENTRA_PIM_TENANT_ID
            or settings.ENTRA_TENANT_ID
        )

        # Resolve client_id (try PIM-specific first, then main)
        pim_client_id = (
            settings.ENTRA_PIM_CLIENT_ID
            or settings.ENTRA_CLIENT_ID
        )

        # Resolve client_secret (vault > env > settings)
        pim_client_secret = (
            vault_pim_secret
            or settings.ENTRA_PIM_CLIENT_SECRET
            or settings.ENTRA_CLIENT_SECRET
        )

        # Step 2: Try DB config for PIM-specific client_id (overrides env/settings)
        try:
            from accounts.models import EntraConfig
            db_config = EntraConfig.get_config()
            if db_config.is_configured():
                db_pim_tenant = getattr(db_config, 'pim_tenant_id', '') or db_config.tenant_id
                db_pim_client_id = getattr(db_config, 'pim_client_id', '') or db_config.client_id
                db_pim_client_secret = getattr(db_config, 'pim_client_secret', '')

                # DB PIM client_id takes precedence over env/settings
                if db_pim_client_id:
                    pim_tenant = db_pim_tenant
                    pim_client_id = db_pim_client_id
                    if db_pim_client_secret:
                        pim_client_secret = db_pim_client_secret
        except Exception as e:
            logger.warning(f'Failed to load PIM config from DB: {e}')

        # Step 3: Now detect environment with the CORRECT client_id resolved
        env_type = self._factory._detect_environment()

        # Step 4: Accept config if we have client_id AND (secret OR cert-based auth)
        if pim_client_id and (pim_client_secret or env_type in ('managed_identity', 'certificate')):
            self._tenant_id = pim_tenant
            self._client_id = pim_client_id
            self._client_secret = pim_client_secret
            logger.info(
                f'Loaded PIM config: '
                f'tenant={pim_tenant} client={pim_client_id[:8]}... '
                f'auth={env_type}'
            )
            return

        # Step 5: Fallback to OIDC app credentials
        self._tenant_id = settings.ENTRA_TENANT_ID
        self._client_id = settings.ENTRA_CLIENT_ID
        self._client_secret = settings.ENTRA_CLIENT_SECRET
        logger.warning(
            'No PIM-specific credentials configured. '
            'Falling back to OIDC app credentials. '
            'For production, configure separate PIM app credentials.'
        )

    def _get_access_token(self) -> Optional[str]:
        """Get an access token for Microsoft Graph API using the credential factory."""
        if self._access_token:
            return self._access_token

        self._load_config()

        if not self._client_id or not self._tenant_id:
            logger.error('PIM credentials not configured')
            return None

        # Use the credential factory to get a token
        token = self._factory.get_graph_token(
            tenant_id=self._tenant_id,
            client_id=self._client_id,
            client_secret=self._client_secret,
        )

        if token:
            self._access_token = token
            return self._access_token
        else:
            logger.error('Failed to acquire Graph API token via credential factory')
            return None

    async def _graph_request(self, method: str, path: str, data: dict = None) -> dict:
        """Make a request to Microsoft Graph API."""
        token = self._get_access_token()
        if not token:
            return {'error': 'No access token available'}

        url = f'{self.GRAPH_API_BASE}{path}'
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json',
        }

        async with httpx.AsyncClient() as client:
            try:
                response = await client.request(method, url, headers=headers, json=data)
                response.raise_for_status()
                return response.json() if response.content else {}
            except httpx.HTTPStatusError as e:
                logger.error(f'Graph API error: {e.response.status_code} {e.response.text}')
                return {'error': str(e)}
            except Exception as e:
                logger.error(f'Graph API request failed: {e}')
                return {'error': str(e)}

    def provision_access(self, user_entra_oid: str, role_config: dict, duration_minutes: int) -> dict:
        """
        Assign a directory role to a user directly (no P2 license needed).

        role_config expects:
            - role_id: str (Entra ID role definition ID)
            - role_name: str (optional)
        """
        role_id = role_config.get('role_id') or role_config.get('entra_role_id')
        if not role_id:
            return {'success': False, 'error': 'No role ID provided'}

        # Load config synchronously BEFORE entering async context
        self._load_config()

        justification = role_config.get('justification', 'PAM JIT elevation request')

        request_body = {
            'principalId': user_entra_oid,
            'roleDefinitionId': role_id,
            'directoryScopeId': '/',
            'justification': justification,
        }

        try:
            result = asyncio.run(
                self._graph_request(
                    'POST',
                    '/roleManagement/directory/roleAssignments',
                    data=request_body,
                )
            )

            if 'error' in result:
                return {'success': False, 'error': result['error']}

            assignment_id = result.get('id', '')
            logger.info(f'Directory role assigned: user={user_entra_oid} role={role_id} assignment_id={assignment_id}')

            return {
                'success': True,
                'reference_id': assignment_id,
                'status': 'activated',
            }

        except Exception as e:
            logger.error(f'Failed to assign directory role: {e}')
            return {'success': False, 'error': str(e)}

    def deprovision_access(self, reference_id: str) -> bool:
        """
        Remove a directory role assignment.
        """
        # Load config synchronously BEFORE entering async context
        self._load_config()

        try:
            result = asyncio.run(
                self._graph_request(
                    'DELETE',
                    f'/roleManagement/directory/roleAssignments/{reference_id}',
                )
            )
            logger.info(f'Directory role assignment removed: id={reference_id}')
            return 'error' not in result

        except Exception as e:
            logger.error(f'Failed to remove directory role assignment: {e}')
            return False

    def list_available_roles(self) -> list[dict]:
        """List all directory roles from Entra ID."""
        try:
            result = asyncio.run(
                self._graph_request('GET', '/roleManagement/directory/roleDefinitions')
            )
            roles = []
            for role_def in result.get('value', []):
                roles.append({
                    'id': role_def['id'],
                    'name': role_def.get('displayName', 'Unknown'),
                    'description': role_def.get('description', ''),
                    'provider': 'ENTRA',
                })
            return roles

        except Exception as e:
            logger.error(f'Failed to list directory roles: {e}')
            return []

    def check_access_status(self, reference_id: str) -> str:
        """Check if a role assignment still exists."""
        try:
            result = asyncio.run(
                self._graph_request(
                    'GET',
                    f'/roleManagement/directory/roleAssignments/{reference_id}',
                )
            )
            if 'error' in result:
                return 'expired'
            return 'active'

        except Exception as e:
            logger.error(f'Failed to check role assignment status: {e}')
            return 'unknown'
