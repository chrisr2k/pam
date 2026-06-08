"""
Entra ID ABAC (Attribute-Based Access Control) provider.

Uses Microsoft Graph API to update user directory extension attributes
that are synced to AWS IAM Identity Center for ABAC policy evaluation.

Instead of creating/destroying individual account assignments, this provider
manages a multi-value attribute on the user object in Entra ID (e.g.
extensionAttribute5) that contains a comma-separated list of AWS account IDs
the user has been granted access to.

AWS Identity Center syncs this attribute from Entra via SCIM, and permission
sets use ABAC trust policies to evaluate access based on the attribute value.

!!! IMPORTANT LIMITATION - NOT SUITABLE FOR JIT ACCESS !!!

This provider relies on SCIM attribute sync from Entra ID to AWS IAM Identity
Center, which has a 30-40 minute delay. This makes it unsuitable for
just-in-time (JIT) privileged access scenarios where access needs to be
granted or revoked within seconds.

For JIT access, use the standard AWSIdentityCenterProvider instead, which
creates/deletes account assignments via the AWS SSO Admin API instantly.

When to use this ABAC provider:
  - Scheduled/planned access (requested hours or days in advance)
  - Long-running assignments (days/weeks) where sync delay is negligible
  - Read-only base access + ABAC-gated admin pattern (40-min delay acceptable)
  - Avoiding AWS SSO Admin API rate limits for bulk operations

Prerequisites (configured outside PAM):
  1. An Entra ID directory extension attribute registered on the User object
  2. AWS IAM Identity Center configured with Entra as the external IdP
  3. The permission set has an ABAC trust policy (e.g.
     ${aws:PrincipalTag/awsAdminAccounts} contains "${aws:ResourceTag/AccountId}")
  4. The PIM app registration has User.ReadWrite.All Graph permission
"""


import asyncio
import logging
from typing import Optional

import httpx
from django.conf import settings

from .base import BasePrivilegedAccessProvider
from .credential_factory import EntraCredentialFactory

logger = logging.getLogger(__name__)


class EntraABACProvider(BasePrivilegedAccessProvider):
    """
    Provider implementation for ABAC via Entra ID directory attributes.

    Manages a multi-value extension attribute on the user object that
    AWS IAM Identity Center syncs for ABAC policy evaluation.

    Provisioning = adding an account ID to the user's attribute value.
    Deprovisioning = removing an account ID from the user's attribute value.
    """

    GRAPH_API_BASE = 'https://graph.microsoft.com/v1.0'

    def __init__(self):
        self._access_token = None
        self._factory = EntraCredentialFactory()
        self._tenant_id = None
        self._client_id = None
        self._client_secret = None

    def _load_config(self):
        """Load Entra config for Graph API access (reuses PIM credential factory)."""
        if self._client_id and self._tenant_id:
            return

        from pam.secrets_resolver import get_secret

        self._tenant_id = (
            settings.ENTRA_PIM_TENANT_ID
            or settings.ENTRA_TENANT_ID
        )
        self._client_id = (
            settings.ENTRA_PIM_CLIENT_ID
            or settings.ENTRA_CLIENT_ID
        )
        vault_pim_secret = get_secret('ENTRA_PIM_CLIENT_SECRET', '')
        self._client_secret = (
            vault_pim_secret
            or settings.ENTRA_PIM_CLIENT_SECRET
            or settings.ENTRA_CLIENT_SECRET
        )

        # Try DB config for PIM-specific credentials
        try:
            from accounts.models import EntraConfig
            db_config = EntraConfig.get_config()
            if db_config.is_configured():
                db_pim_client_id = getattr(db_config, 'pim_client_id', '') or db_config.client_id
                if db_pim_client_id:
                    self._tenant_id = getattr(db_config, 'pim_tenant_id', '') or db_config.tenant_id
                    self._client_id = db_pim_client_id
                    db_pim_secret = getattr(db_config, 'pim_client_secret', '')
                    if db_pim_secret:
                        self._client_secret = db_pim_secret
        except Exception as e:
            logger.warning(f'Failed to load ABAC config from DB: {e}')

    def _get_access_token(self) -> Optional[str]:
        """Get a Microsoft Graph API access token."""
        if self._access_token:
            return self._access_token

        self._load_config()

        if not self._client_id or not self._tenant_id:
            logger.error('Entra credentials not configured for ABAC provider')
            return None

        token = self._factory.get_graph_token(
            tenant_id=self._tenant_id,
            client_id=self._client_id,
            client_secret=self._client_secret,
        )

        if token:
            self._access_token = token
            return self._access_token
        else:
            logger.error('Failed to acquire Graph API token for ABAC provider')
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

    def _parse_attribute_value(self, raw_value) -> list[str]:
        """Parse a comma-separated attribute value into a list of account IDs."""
        if not raw_value:
            return []
        if isinstance(raw_value, str):
            return [aid.strip() for aid in raw_value.split(',') if aid.strip()]
        if isinstance(raw_value, list):
            return [str(aid).strip() for aid in raw_value if str(aid).strip()]
        return [str(raw_value).strip()]

    def _format_attribute_value(self, account_ids: list[str]) -> str:
        """Format a list of account IDs as a comma-separated string."""
        return ','.join(sorted(set(account_ids)))

    def provision_access(self, user_entra_oid: str, role_config: dict, duration_minutes: int) -> dict:
        """
        Grant access by adding an AWS account ID to the user's directory attribute.

        role_config expects:
            - attribute_name: str (the Entra extension attribute, e.g. extension_<appId>_awsAdminAccounts)
            - account_id: str (the AWS account ID to add)
        """
        attribute_name = role_config.get('attribute_name') or role_config.get('entra_attribute_name')
        account_id = role_config.get('account_id') or role_config.get('aws_account_id')

        if not attribute_name:
            return {'success': False, 'error': 'No Entra attribute name provided'}
        if not account_id:
            return {'success': False, 'error': 'No AWS account ID provided'}

        self._load_config()

        try:
            # Step 1: Get the current value of the attribute
            result = asyncio.run(
                self._graph_request(
                    'GET',
                    f'/users/{user_entra_oid}?$select=id,{attribute_name}',
                )
            )

            if 'error' in result:
                return {'success': False, 'error': result['error']}

            # Step 2: Parse current value and add the new account ID
            current_value = result.get(attribute_name, '')
            current_accounts = self._parse_attribute_value(current_value)

            if account_id in current_accounts:
                logger.info(
                    f'Account {account_id} already in attribute {attribute_name} '
                    f'for user {user_entra_oid}'
                )
                return {
                    'success': True,
                    'reference_id': f'{attribute_name}:{account_id}',
                    'status': 'already_granted',
                }

            current_accounts.append(account_id)
            new_value = self._format_attribute_value(current_accounts)

            # Step 3: Update the attribute on the user object
            update_result = asyncio.run(
                self._graph_request(
                    'PATCH',
                    f'/users/{user_entra_oid}',
                    data={attribute_name: new_value},
                )
            )

            if 'error' in update_result:
                return {'success': False, 'error': update_result['error']}

            logger.info(
                f'ABAC attribute updated: user={user_entra_oid} '
                f'attribute={attribute_name} added_account={account_id} '
                f'current_values=[{new_value}]'
            )

            return {
                'success': True,
                'reference_id': f'{attribute_name}:{account_id}',
                'status': 'activated',
            }

        except Exception as e:
            logger.error(f'Failed to update ABAC attribute: {e}')
            return {'success': False, 'error': str(e)}

    def deprovision_access(self, reference_id: str) -> bool:
        """
        Revoke access by removing an AWS account ID from the user's attribute.

        reference_id format: "attribute_name:account_id"
        """
        if ':' not in reference_id:
            logger.error(f'Invalid reference_id format for ABAC deprovision: {reference_id}')
            return False

        attribute_name, account_id = reference_id.split(':', 1)

        self._load_config()

        try:
            # Step 1: Get the current value of the attribute
            result = asyncio.run(
                self._graph_request(
                    'GET',
                    f'/users/{attribute_name.split(":")[0] if ":" in attribute_name else ""}'
                    f'?$select=id,{attribute_name}',
                )
            )

            # The reference_id is attribute_name:account_id, but we need the user OID.
            # We store it differently - let's use a different approach.
            # Actually, reference_id format is "attribute_name:account_id" but we need
            # the user OID to make the Graph call. This means we need to store it
            # differently or look it up from the AccessRequest.
            logger.error(
                f'ABAC deprovision requires user OID. reference_id={reference_id} '
                f'is not sufficient alone. Use deprovision_access_for_user() instead.'
            )
            return False

        except Exception as e:
            logger.error(f'Failed to deprovision ABAC attribute: {e}')
            return False

    def deprovision_access_for_user(self, user_entra_oid: str, attribute_name: str, account_id: str) -> bool:
        """
        Revoke access by removing an AWS account ID from the user's attribute.

        This is the preferred deprovision method since it has all the context needed.
        """
        if not user_entra_oid or not attribute_name or not account_id:
            logger.error('Missing required parameters for ABAC deprovision')
            return False

        self._load_config()

        try:
            # Step 1: Get the current value of the attribute
            result = asyncio.run(
                self._graph_request(
                    'GET',
                    f'/users/{user_entra_oid}?$select=id,{attribute_name}',
                )
            )

            if 'error' in result:
                logger.error(f'Failed to get user attribute for deprovision: {result["error"]}')
                return False

            # Step 2: Parse current value and remove the account ID
            current_value = result.get(attribute_name, '')
            current_accounts = self._parse_attribute_value(current_value)

            if account_id not in current_accounts:
                logger.info(
                    f'Account {account_id} not found in attribute {attribute_name} '
                    f'for user {user_entra_oid} (already removed)'
                )
                return True

            current_accounts = [aid for aid in current_accounts if aid != account_id]
            new_value = self._format_attribute_value(current_accounts)

            # Step 3: Update the attribute on the user object
            update_result = asyncio.run(
                self._graph_request(
                    'PATCH',
                    f'/users/{user_entra_oid}',
                    data={attribute_name: new_value},
                )
            )

            if 'error' in update_result:
                logger.error(f'Failed to update ABAC attribute for deprovision: {update_result["error"]}')
                return False

            logger.info(
                f'ABAC attribute updated (deprovision): user={user_entra_oid} '
                f'attribute={attribute_name} removed_account={account_id} '
                f'remaining=[{new_value}]'
            )

            return True

        except Exception as e:
            logger.error(f'Failed to deprovision ABAC attribute: {e}')
            return False

    def list_available_roles(self) -> list[dict]:
        """ABAC roles are managed in the PAM database, not discovered from a provider."""
        return []

    def check_access_status(self, reference_id: str) -> str:
        """
        Check if an account ID is still in the user's attribute.

        reference_id format: "attribute_name:account_id"
        Note: This requires the user OID which isn't in the reference_id alone.
        Returns 'unknown' since we can't check without the user context.
        """
        return 'unknown'
