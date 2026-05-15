import asyncio
import logging
from datetime import datetime, timedelta
from typing import Optional

import httpx
from django.conf import settings
from django.contrib.auth import get_user_model

from .base import BasePrivilegedAccessProvider

logger = logging.getLogger(__name__)

User = get_user_model()


class EntraPIMProvider(BasePrivilegedAccessProvider):
    """
    Provider implementation for Entra ID privileged access management.
    Uses Microsoft Graph API to assign/unassign directory roles directly.
    This works with any Entra ID license tier (no P2 license required).

    How it works:
    - Provision: Creates a permanent role assignment via adminAssign
    - Deprovision: Deletes the role assignment to remove access
    - The PAM app manages the timer and deprovisions automatically
    """

    GRAPH_API_BASE = 'https://graph.microsoft.com/v1.0'

    def __init__(self):
        self._access_token = None
        self._authority = None
        self._client_id = None
        self._client_secret = None

    def _load_config(self):
        """Load Entra config from DB or settings."""
        if self._client_id and self._client_secret:
            return
        try:
            from accounts.models import EntraConfig
            db_config = EntraConfig.get_config()
            if db_config.is_configured():
                self._authority = f'https://login.microsoftonline.com/{db_config.tenant_id}'
                self._client_id = db_config.client_id
                self._client_secret = db_config.get_client_secret()
                logger.info(f'Loaded Entra config from DB: tenant={db_config.tenant_id}')
                return
        except Exception as e:
            logger.warning(f'Failed to load Entra config from DB: {e}')
        self._authority = settings.ENTRA_AUTHORITY
        self._client_id = settings.ENTRA_CLIENT_ID
        self._client_secret = settings.ENTRA_CLIENT_SECRET
        logger.info(f'Fell back to settings: authority={self._authority}')

    def _get_access_token(self) -> Optional[str]:
        """Get an access token for Microsoft Graph API using client credentials."""
        if self._access_token:
            return self._access_token

        self._load_config()

        import msal
        app = msal.ConfidentialClientApplication(
            client_id=self._client_id,
            client_credential=self._client_secret,
            authority=self._authority,
        )

        result = app.acquire_token_for_client(
            scopes=['https://graph.microsoft.com/.default']
        )

        if 'access_token' in result:
            self._access_token = result['access_token']
            return self._access_token
        else:
            logger.error(f'Failed to acquire Graph API token: {result.get("error_description")}')
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
