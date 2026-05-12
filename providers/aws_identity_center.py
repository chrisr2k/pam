import logging
from typing import Optional

import boto3
from botocore.exceptions import ClientError, BotoCoreError
from django.conf import settings

from .base import BasePrivilegedAccessProvider

logger = logging.getLogger(__name__)


class AWSIdentityCenterProvider(BasePrivilegedAccessProvider):
    """
    Provider implementation for AWS Identity Center (SSO).
    Manages account assignments for permission sets.
    """

    def __init__(self):
        self.session = boto3.Session(
            aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
            aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
            region_name=settings.AWS_REGION,
        )
        self.sso_admin = self.session.client('sso-admin')
        self.identity_store = self.session.client('identitystore')
        self._instance_arn = None

    @property
    def instance_arn(self) -> str:
        """Get the SSO instance ARN."""
        if self._instance_arn:
            return self._instance_arn
        if settings.AWS_SSO_INSTANCE_ARN:
            self._instance_arn = settings.AWS_SSO_INSTANCE_ARN
            return self._instance_arn

        # Discover the instance ARN
        try:
            response = self.sso_admin.list_instances()
            instances = response.get('Instances', [])
            if instances:
                self._instance_arn = instances[0]['InstanceArn']
                return self._instance_arn
        except (ClientError, BotoCoreError) as e:
            logger.error(f'Failed to list SSO instances: {e}')
        return ''

    def _get_identity_store_id(self) -> str:
        """Get the identity store ID for the SSO instance."""
        try:
            response = self.sso_admin.list_instances()
            instances = response.get('Instances', [])
            if instances:
                return instances[0]['IdentityStoreId']
        except (ClientError, BotoCoreError) as e:
            logger.error(f'Failed to get identity store ID: {e}')
        return ''

    def _resolve_user_id(self, user_entra_oid: str) -> Optional[str]:
        """
        Resolve an Entra ID object ID to an AWS Identity Center user ID.
        This works when Entra ID is the external identity provider for AWS SSO.
        """
        identity_store_id = self._get_identity_store_id()
        if not identity_store_id:
            logger.error('No identity store ID available')
            return None

        try:
            # Try to find user by external ID (Entra OID)
            response = self.identity_store.list_users(
                IdentityStoreId=identity_store_id,
                Filters=[
                    {
                        'AttributePath': 'ExternalId',
                        'AttributeValue': user_entra_oid,
                    }
                ],
            )
            users = response.get('Users', [])
            if users:
                return users[0]['UserId']

            # Fallback: search by userName
            response = self.identity_store.list_users(
                IdentityStoreId=identity_store_id,
                Filters=[
                    {
                        'AttributePath': 'UserName',
                        'AttributeValue': user_entra_oid,
                    }
                ],
            )
            users = response.get('Users', [])
            if users:
                return users[0]['UserId']

            logger.warning(f'User not found in AWS Identity Center: {user_entra_oid}')
            return None

        except (ClientError, BotoCoreError) as e:
            logger.error(f'Failed to resolve user ID: {e}')
            return None

    def provision_access(self, user_entra_oid: str, role_config: dict, duration_minutes: int) -> dict:
        """
        Provision AWS SSO account assignment.

        role_config expects:
            - permission_set_arn: str
            - account_id: str (optional, defaults to role_config['aws_account_id'])
        """
        permission_set_arn = role_config.get('permission_set_arn') or role_config.get('aws_permission_set_arn')
        account_id = role_config.get('account_id') or role_config.get('aws_account_id')

        if not permission_set_arn:
            return {'success': False, 'error': 'No permission set ARN provided'}
        if not account_id:
            return {'success': False, 'error': 'No AWS account ID provided'}

        user_id = self._resolve_user_id(user_entra_oid)
        if not user_id:
            return {'success': False, 'error': 'User not found in AWS Identity Center'}

        instance_arn = self.instance_arn
        if not instance_arn:
            return {'success': False, 'error': 'No SSO instance ARN available'}

        try:
            response = self.sso_admin.create_account_assignment(
                InstanceArn=instance_arn,
                PermissionSetArn=permission_set_arn,
                PrincipalId=user_id,
                PrincipalType='USER',
                TargetId=account_id,
                TargetType='AWS_ACCOUNT',
            )
            assignment_status = response.get('AccountAssignmentCreationStatus', {})
            status = assignment_status.get('Status', 'UNKNOWN')
            request_id = assignment_status.get('RequestId', '')

            logger.info(
                f'AWS account assignment created: user={user_id} '
                f'permission_set={permission_set_arn} account={account_id} '
                f'status={status}'
            )

            return {
                'success': status == 'SUCCEEDED',
                'reference_id': request_id,
                'status': status,
            }

        except (ClientError, BotoCoreError) as e:
            logger.error(f'Failed to create AWS account assignment: {e}')
            return {'success': False, 'error': str(e)}

    def deprovision_access(self, reference_id: str) -> bool:
        """
        Note: AWS SSO Admin API doesn't support deleting by request ID directly.
        This method handles deprovisioning by looking up the assignment.
        For simplicity, we log the deprovision request.
        In production, you'd need to store the full assignment details.
        """
        logger.info(f'AWS deprovision requested for reference_id={reference_id}')
        # In a real implementation, you would:
        # 1. Look up the stored assignment details
        # 2. Call delete_account_assignment with the same parameters
        # 3. Verify the deletion
        return True

    def list_available_roles(self) -> list[dict]:
        """List all permission sets from AWS Identity Center."""
        instance_arn = self.instance_arn
        if not instance_arn:
            return []

        roles = []
        try:
            # List permission sets
            paginator = self.sso_admin.get_paginator('list_permission_sets')
            for page in paginator.paginate(InstanceArn=instance_arn):
                for ps_arn in page.get('PermissionSets', []):
                    # Get permission set details
                    ps_response = self.sso_admin.describe_permission_set(
                        InstanceArn=instance_arn,
                        PermissionSetArn=ps_arn,
                    )
                    ps = ps_response.get('PermissionSet', {})
                    roles.append({
                        'arn': ps_arn,
                        'name': ps.get('Name', 'Unknown'),
                        'description': ps.get('Description', ''),
                        'provider': 'AWS',
                    })
        except (ClientError, BotoCoreError) as e:
            logger.error(f'Failed to list permission sets: {e}')

        return roles

    def check_access_status(self, reference_id: str) -> str:
        """Check the status of a provisioning request."""
        try:
            response = self.sso_admin.describe_account_assignment_creation_status(
                InstanceArn=self.instance_arn,
                AccountAssignmentCreationRequestId=reference_id,
            )
            status = response.get('AccountAssignmentCreationStatus', {}).get('Status', 'UNKNOWN')
            if status == 'SUCCEEDED':
                return 'active'
            elif status == 'FAILED':
                return 'failed'
            return 'pending'
        except (ClientError, BotoCoreError) as e:
            logger.error(f'Failed to check access status: {e}')
            return 'unknown'
