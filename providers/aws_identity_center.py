import logging
import os
from typing import Optional

import boto3
from botocore.exceptions import ClientError, BotoCoreError
from django.conf import settings

from accounts.models import AWSConfig
from .base import BasePrivilegedAccessProvider

logger = logging.getLogger(__name__)


class AWSIdentityCenterProvider(BasePrivilegedAccessProvider):
    """
    Provider implementation for AWS Identity Center (SSO).
    Manages account assignments for permission sets.

    Credentials are resolved in this order:
      1. IAM Instance Profile (auto-detected when running on AWS)
      2. IAM Roles Anywhere (certificate-based, for on-prem/OCI)
      3. STS AssumeRole (role chaining)
      4. IAM User access keys (dev only - fallback)
    """

    def __init__(self):
        self.config = AWSConfig.get_config()
        self._session = None
        self._sso_admin = None
        self._identity_store = None
        self._instance_arn = None

    def _get_session(self) -> boto3.Session:
        """Create a boto3 session using the configured auth method."""
        if self._session:
            return self._session

        region = self.config.region or 'us-east-1'
        auth_method = self.config.get_auth_method()

        if auth_method == 'iam_user':
            # Dev only - long-lived IAM user keys
            self._session = boto3.Session(
                aws_access_key_id=self.config.access_key_id,
                aws_secret_access_key=self.config.secret_access_key,
                region_name=region,
            )
        elif auth_method == 'assume_role':
            # STS AssumeRole - use current identity to assume the configured role
            base_session = boto3.Session(region_name=region)
            sts = base_session.client('sts')
            assume_kwargs = {
                'RoleArn': self.config.role_arn,
                'RoleSessionName': self.config.role_session_name or 'PAM-Session',
            }
            if self.config.external_id:
                assume_kwargs['ExternalId'] = self.config.external_id
            response = sts.assume_role(**assume_kwargs)
            creds = response['Credentials']
            self._session = boto3.Session(
                aws_access_key_id=creds['AccessKeyId'],
                aws_secret_access_key=creds['SecretAccessKey'],
                aws_session_token=creds['SessionToken'],
                region_name=region,
            )
        elif auth_method == 'roles_anywhere':
            # IAM Roles Anywhere - pure Python implementation
            # Uses the certificate + private key to call the Roles Anywhere
            # CreateSession API directly. No external binary needed.
            self._session = self._get_roles_anywhere_session(region)
        else:
            # Instance profile (default when running on AWS)
            self._session = boto3.Session(region_name=region)

        return self._session

    def _get_roles_anywhere_session(self, region: str) -> boto3.Session:
        """Get a boto3 session using IAM Roles Anywhere with pure Python.

        Uses the client certificate's private key to create an AWS SigV4-signed
        request to the Roles Anywhere CreateSession API. No external binary
        (aws_signing_helper) required - works on any platform.
        """
        cert_path = os.getenv('AWS_ROLES_ANYWHERE_CERT_PATH', '')
        key_path = os.getenv('AWS_ROLES_ANYWHERE_KEY_PATH', '')
        # role_arn = the IAM role to assume via Roles Anywhere
        # profile_arn = the Roles Anywhere trust profile ARN (required by CreateSession API)
        # trust_arn = the trust anchor ARN (optional)
        role_arn = self.config.role_arn
        profile_arn = self.config.roles_anywhere_profile_arn
        trust_arn = self.config.roles_anywhere_trust_arn
        profile_name = os.getenv('AWS_ROLES_ANYWHERE_PROFILE_NAME', 'prod-rolesanywhere-profile')

        if not (cert_path and key_path and os.path.exists(cert_path) and os.path.exists(key_path)):
            logger.warning(
                f'Roles Anywhere configured but cert/key not found. '
                f'cert_path={cert_path!r} exists={os.path.exists(cert_path) if cert_path else False}, '
                f'key_path={key_path!r} exists={os.path.exists(key_path) if key_path else False}'
            )
            return boto3.Session(region_name=region)

        if not profile_arn:
            logger.warning(
                'Roles Anywhere cert files found but no roles_anywhere_profile_arn configured. '
                'Set roles_anywhere_profile_arn in the database or '
                'AWS_ROLES_ANYWHERE_PROFILE_NAME env var for auto-discovery.'
            )
            return boto3.Session(region_name=region)

        try:
            import base64
            import hashlib
            import json
            import uuid
            from datetime import datetime

            import requests

            # ── Load the client certificate and CA chain ──
            from cryptography import x509
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import padding

            with open(cert_path, 'rb') as f:
                cert = x509.load_pem_x509_certificate(f.read())
            with open(key_path, 'rb') as f:
                private_key = serialization.load_pem_private_key(f.read(), password=None)

            # Roles Anywhere requires:
            #   X-Amz-X509: base64-encoded DER client certificate
            #   X-Amz-X509-Chain: comma-delimited, base64-encoded DER of the CA chain
            #   Credential in Authorization: decimal serial number of the signing certificate
            cert_der = cert.public_bytes(serialization.Encoding.DER)
            cert_b64 = base64.b64encode(cert_der).decode('ascii')
            cert_serial = str(cert.serial_number)

            # Build the certificate chain (X-Amz-X509-Chain)
            # The chain is comma-delimited base64-encoded DER certificates,
            # ordered from the signing CA up to the root CA.
            # Try to find the CA cert that signed the client cert.
            chain_b64 = ''
            ca_cert_path = os.getenv('AWS_ROLES_ANYWHERE_CA_CERT_PATH', '')
            if not ca_cert_path:
                # Default: look for ca-cert.pem next to client.crt
                ca_dir = os.path.dirname(cert_path)
                ca_cert_path = os.path.join(ca_dir, 'ca-cert.pem')
            if os.path.exists(ca_cert_path):
                try:
                    with open(ca_cert_path, 'rb') as f:
                        ca_cert_data = f.read()
                    ca_cert = x509.load_pem_x509_certificate(ca_cert_data)
                    ca_der = ca_cert.public_bytes(serialization.Encoding.DER)
                    chain_b64 = base64.b64encode(ca_der).decode('ascii')
                    logger.info(f'Loaded CA cert chain from {ca_cert_path}')
                except Exception as e:
                    logger.warning(f'Failed to load CA cert from {ca_cert_path}: {e}')
            else:
                logger.debug(f'No CA cert found at {ca_cert_path}, skipping X-Amz-X509-Chain')

            # ── Build the CreateSession request ──
            service = 'rolesanywhere'
            host = f'rolesanywhere.{region}.amazonaws.com'
            endpoint = f'https://{host}/sessions'
            method = 'POST'

            # For Roles Anywhere CreateSession API:
            #   - profileArn: Roles Anywhere trust profile ARN (required)
            #   - roleArn: IAM role ARN to assume (optional if profile has it)
            #   - trustAnchorArn: Trust anchor ARN (optional if profileArn is set)
            body = {
                'roleArn': role_arn,
                'sessionName': f'PAM-Session-{uuid.uuid4().hex[:8]}',
            }
            if profile_arn:
                body['profileArn'] = profile_arn
            elif trust_arn:
                # Profile ARN not configured - try to discover it by name
                # using the Roles Anywhere ListProfiles API
                discovered = self._discover_roles_anywhere_profile(
                    region, cert, private_key, cert_b64, cert_serial,
                    profile_name, trust_arn
                )
                if discovered:
                    body['profileArn'] = discovered
                    logger.info(f'Discovered Roles Anywhere profile: {discovered}')
                else:
                    logger.warning(
                        f'Could not discover Roles Anywhere profile "{profile_name}". '
                        f'Set AWS_ROLES_ANYWHERE_PROFILE_NAME env var or configure '
                        f'roles_anywhere_profile_arn in the database.'
                    )
            if trust_arn:
                body['trustAnchorArn'] = trust_arn

            body_bytes = json.dumps(body).encode('utf-8')
            body_hash = hashlib.sha256(body_bytes).hexdigest()

            # ── SigV4 signing ──
            # IAM Roles Anywhere uses a special signing mechanism where the
            # X.509 certificate's private key signs the SigV4 string-to-sign.
            # The credential scope uses the cert hash as the access key.
            algorithm = 'AWS4-X509-RSA-SHA256'
            now = datetime.utcnow()
            amz_date = now.strftime('%Y%m%dT%H%M%SZ')
            date_stamp = now.strftime('%Y%m%d')

            # Credential scope
            credential_scope = f'{date_stamp}/{region}/{service}/aws4_request'

            # Canonical request
            canonical_uri = '/sessions'
            canonical_querystring = ''

            # Include X-Amz-X509-Chain in signed headers if we have a chain
            if chain_b64:
                signed_headers = 'content-type;host;x-amz-date;x-amz-x509;x-amz-x509-chain'
                canonical_headers = (
                    f'content-type:application/json\n'
                    f'host:{host}\n'
                    f'x-amz-date:{amz_date}\n'
                    f'x-amz-x509:{cert_b64}\n'
                    f'x-amz-x509-chain:{chain_b64}\n'
                )
            else:
                signed_headers = 'content-type;host;x-amz-date;x-amz-x509'
                canonical_headers = (
                    f'content-type:application/json\n'
                    f'host:{host}\n'
                    f'x-amz-date:{amz_date}\n'
                    f'x-amz-x509:{cert_b64}\n'
                )

            canonical_request = (
                f'{method}\n'
                f'{canonical_uri}\n'
                f'{canonical_querystring}\n'
                f'{canonical_headers}\n'
                f'{signed_headers}\n'
                f'{body_hash}'
            )

            # String to sign
            string_to_sign = (
                f'{algorithm}\n'
                f'{amz_date}\n'
                f'{credential_scope}\n'
                f'{hashlib.sha256(canonical_request.encode("utf-8")).hexdigest()}'
            )

            # Sign with the private key (RSA-SHA256)
            signature = private_key.sign(
                string_to_sign.encode('utf-8'),
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
            signature_hex = signature.hex()

            # Build the authorization header
            # Credential uses the decimal serial number of the signing certificate
            authorization_header = (
                f'{algorithm} '
                f'Credential={cert_serial}/{credential_scope}, '
                f'SignedHeaders={signed_headers}, '
                f'Signature={signature_hex}'
            )

            # ── Make the API call ──
            headers = {
                'Content-Type': 'application/json',
                'X-Amz-Date': amz_date,
                'X-Amz-X509': cert_b64,
                'Authorization': authorization_header,
            }
            if chain_b64:
                headers['X-Amz-X509-Chain'] = chain_b64

            logger.info(f'Calling Roles Anywhere CreateSession for role {role_arn}')

            response = requests.post(
                endpoint,
                json=body,
                headers=headers,
                timeout=30,
            )
            response.raise_for_status()
            data = response.json()

            # Parse the credential set from the response
            credential_set = data.get('credentialSet', [{}])[0]
            credentials = credential_set.get('credentials', {})

            access_key = credentials.get('accessKeyId') or credentials.get('AccessKeyId')
            secret_key = credentials.get('secretAccessKey') or credentials.get('SecretAccessKey')
            session_token = credentials.get('sessionToken') or credentials.get('SessionToken')

            if not all([access_key, secret_key, session_token]):
                logger.error(f'Incomplete credentials from Roles Anywhere: {credentials}')
                return boto3.Session(region_name=region)

            logger.info('Successfully obtained Roles Anywhere credentials via Python')
            return boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
                aws_session_token=session_token,
                region_name=region,
            )

        except ImportError as e:
            logger.error(f'Missing library for Roles Anywhere: {e}. '
                         f'Install with: pip install cryptography requests')
            return boto3.Session(region_name=region)
        except requests.exceptions.RequestException as e:
            logger.error(f'Roles Anywhere API request failed: {e}')
            if hasattr(e, 'response') and e.response is not None:
                logger.error(f'Response body: {e.response.text}')
            return boto3.Session(region_name=region)
        except (KeyError, json.JSONDecodeError, ValueError) as e:
            logger.error(f'Roles Anywhere response parse error: {e}')
            return boto3.Session(region_name=region)
        except Exception as e:
            logger.error(f'Roles Anywhere unexpected error: {e}')
            import traceback
            logger.error(traceback.format_exc())
            return boto3.Session(region_name=region)

    def _discover_roles_anywhere_profile(
        self,
        region: str,
        cert,
        private_key,
        cert_b64: str,
        cert_serial: str,
        profile_name: str,
        trust_arn: str,
    ) -> Optional[str]:
        """Discover a Roles Anywhere profile ARN by name.

        Uses the same certificate-based SigV4 signing to call the
        ListProfiles API and find a profile matching the given name.
        """
        try:
            import base64
            import hashlib
            import json
            from datetime import datetime

            import requests
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import padding

            service = 'rolesanywhere'
            host = f'rolesanywhere.{region}.amazonaws.com'
            endpoint = f'https://{host}/profiles'
            method = 'GET'

            algorithm = 'AWS4-X509-RSA-SHA256'
            now = datetime.utcnow()
            amz_date = now.strftime('%Y%m%dT%H%M%SZ')
            date_stamp = now.strftime('%Y%m%d')
            credential_scope = f'{date_stamp}/{region}/{service}/aws4_request'

            canonical_uri = '/profiles'
            canonical_querystring = ''
            signed_headers = 'host;x-amz-date;x-amz-x509'
            canonical_headers = (
                f'host:{host}\n'
                f'x-amz-date:{amz_date}\n'
                f'x-amz-x509:{cert_b64}\n'
            )
            body_hash = hashlib.sha256(b'').hexdigest()

            canonical_request = (
                f'{method}\n{canonical_uri}\n{canonical_querystring}\n'
                f'{canonical_headers}\n{signed_headers}\n{body_hash}'
            )

            string_to_sign = (
                f'{algorithm}\n{amz_date}\n{credential_scope}\n'
                f'{hashlib.sha256(canonical_request.encode()).hexdigest()}'
            )

            signature = private_key.sign(
                string_to_sign.encode(),
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
            signature_hex = signature.hex()

            authorization_header = (
                f'{algorithm} Credential={cert_serial}/{credential_scope}, '
                f'SignedHeaders={signed_headers}, Signature={signature_hex}'
            )

            headers = {
                'X-Amz-Date': amz_date,
                'X-Amz-X509': cert_b64,
                'Authorization': authorization_header,
            }

            logger.info(f'Discovering Roles Anywhere profile by name: {profile_name}')
            response = requests.get(endpoint, headers=headers, timeout=30)

            if response.status_code == 200:
                data = response.json()
                profiles = data.get('profiles', [])
                for profile in profiles:
                    if profile.get('name') == profile_name:
                        profile_arn = profile.get('profileArn')
                        if profile_arn:
                            logger.info(f'Found profile "{profile_name}": {profile_arn}')
                            return profile_arn

                logger.warning(
                    f'Profile "{profile_name}" not found. '
                    f'Available profiles: {[p.get("name") for p in profiles]}'
                )
            else:
                logger.warning(
                    f'Failed to list profiles (status {response.status_code}): '
                    f'{response.text}'
                )

        except Exception as e:
            logger.warning(f'Error discovering Roles Anywhere profile: {e}')

        return None

    @property
    def sso_admin(self):
        if not self._sso_admin:
            self._sso_admin = self._get_session().client('sso-admin')
        return self._sso_admin

    @property
    def identity_store(self):
        if not self._identity_store:
            self._identity_store = self._get_session().client('identitystore')
        return self._identity_store

    @property
    def instance_arn(self) -> str:
        """Get the SSO instance ARN."""
        if self._instance_arn:
            return self._instance_arn
        if self.config.sso_instance_arn:
            self._instance_arn = self.config.sso_instance_arn
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

        The Identity Store ListUsers API only supports filtering by 'UserName'.
        For SCIM-provisioned users, we must list all users and search by
        ExternalIds array client-side.

        Search order:
          1. UserName filter (UPN format - e.g. chrisr@chrisrtest.onmicrosoft.com)
          2. List all users and search ExternalIds array for the Entra OID
          3. List all users and search by email address
        """
        identity_store_id = self._get_identity_store_id()
        if not identity_store_id:
            logger.error('No identity store ID available')
            return None

        try:
            # 1. Try to find user by UserName (UPN format)
            # The Identity Store API only supports filtering by UserName
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
                logger.info(f'Found user by UserName: {users[0]["UserId"]}')
                return users[0]['UserId']

            # 2. List ALL users and search by ExternalIds array
            # SCIM-provisioned users have their Entra OID stored in ExternalIds
            logger.info(f'UserName lookup failed for {user_entra_oid}, listing all users to search by ExternalId')
            paginator = self.identity_store.get_paginator('list_users')
            for page in paginator.paginate(IdentityStoreId=identity_store_id):
                for aws_user in page.get('Users', []):
                    # Check ExternalIds array for matching Entra OID
                    external_ids = aws_user.get('ExternalIds', [])
                    for ext_id in external_ids:
                        if ext_id.get('Id') == user_entra_oid:
                            logger.info(f'Found user by ExternalId: {aws_user["UserId"]}')
                            return aws_user['UserId']

            # 3. Fallback: list all users and search by email
            logger.info(f'ExternalId lookup failed for {user_entra_oid}, searching by email')
            paginator = self.identity_store.get_paginator('list_users')
            for page in paginator.paginate(IdentityStoreId=identity_store_id):
                for aws_user in page.get('Users', []):
                    emails = aws_user.get('Emails', [])
                    for email in emails:
                        if email.get('Value', '').lower() == user_entra_oid.lower():
                            logger.info(f'Found user by Email: {aws_user["UserId"]}')
                            return aws_user['UserId']

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

            # IN_PROGRESS is also a success - the assignment was submitted
            # and will complete asynchronously. We store the full assignment
            # details as JSON so deprovision_access can call DeleteAccountAssignment.
            import json
            reference_id = json.dumps({
                'request_id': request_id,
                'permission_set_arn': permission_set_arn,
                'account_id': account_id,
                'principal_id': user_id,
                'principal_type': 'USER',
            })

            is_success = status in ('SUCCEEDED', 'IN_PROGRESS')
            if not is_success:
                logger.error(f'AWS account assignment failed with status: {status}')

            return {
                'success': is_success,
                'reference_id': reference_id,
                'status': status,
            }

        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            error_msg = str(e)

            # ConflictException means the assignment already exists - treat as success
            if error_code == 'ConflictException':
                logger.info(f'Account assignment already exists for user {user_id}, treating as success')
                import json
                reference_id = json.dumps({
                    'request_id': '',
                    'permission_set_arn': permission_set_arn,
                    'account_id': account_id,
                    'principal_id': user_id,
                    'principal_type': 'USER',
                })
                return {
                    'success': True,
                    'reference_id': reference_id,
                    'status': 'ALREADY_EXISTS',
                }

            logger.error(f'Failed to create AWS account assignment: {error_msg}')
            return {'success': False, 'error': error_msg}
        except BotoCoreError as e:
            logger.error(f'Failed to create AWS account assignment: {e}')
            return {'success': False, 'error': str(e)}

    def deprovision_access(self, reference_id: str) -> bool:
        """
        Deprovision an AWS SSO account assignment by calling DeleteAccountAssignment.

        The reference_id is expected to be a JSON string containing the full
        assignment details (permission_set_arn, account_id, principal_id, principal_type)
        as stored by provision_access.

        For backward compatibility, if reference_id is a plain request_id string
        (not JSON), we log a warning and return True without calling the API,
        since we don't have the full assignment details to delete.
        """
        logger.info(f'AWS deprovision requested for reference_id={reference_id}')

        if not reference_id:
            logger.error('No reference_id provided for deprovision')
            return False

        # Parse the JSON reference_id to get assignment details
        import json
        try:
            assignment = json.loads(reference_id)
        except (json.JSONDecodeError, ValueError):
            # Backward compatibility: old format was just a request_id string
            logger.warning(
                f'Old-format reference_id (not JSON): {reference_id}. '
                f'Cannot delete account assignment without full details. '
                f'Marking as expired.'
            )
            return True

        permission_set_arn = assignment.get('permission_set_arn')
        account_id = assignment.get('account_id')
        principal_id = assignment.get('principal_id')
        principal_type = assignment.get('principal_type', 'USER')

        if not all([permission_set_arn, account_id, principal_id]):
            logger.error(f'Incomplete assignment details in reference_id: {assignment}')
            return False

        instance_arn = self.instance_arn
        if not instance_arn:
            logger.error('No SSO instance ARN available')
            return False

        try:
            response = self.sso_admin.delete_account_assignment(
                InstanceArn=instance_arn,
                PermissionSetArn=permission_set_arn,
                PrincipalId=principal_id,
                PrincipalType=principal_type,
                TargetId=account_id,
                TargetType='AWS_ACCOUNT',
            )
            status = response.get('AccountAssignmentDeletionStatus', {}).get('Status', 'UNKNOWN')
            logger.info(
                f'AWS account assignment deleted: principal={principal_id} '
                f'permission_set={permission_set_arn} account={account_id} '
                f'status={status}'
            )
            # SUCCEEDED or IN_PROGRESS are both acceptable
            return status in ('SUCCEEDED', 'IN_PROGRESS')

        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            error_msg = str(e)

            # ResourceNotFoundException means the assignment was already deleted
            if error_code == 'ResourceNotFoundException':
                logger.info(f'Account assignment already deleted (not found): {error_msg}')
                return True

            logger.error(f'Failed to delete AWS account assignment: {error_msg}')
            return False
        except BotoCoreError as e:
            logger.error(f'Failed to delete AWS account assignment: {e}')
            return False

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
        """Check the status of a provisioning request.

        The reference_id is expected to be a JSON string containing the
        assignment details (including request_id).
        """
        # Parse the JSON reference_id to extract the request_id
        import json
        try:
            assignment = json.loads(reference_id)
            request_id = assignment.get('request_id', '')
        except (json.JSONDecodeError, ValueError):
            # Fallback: treat reference_id as a raw request_id (legacy format)
            request_id = reference_id

        if not request_id:
            logger.warning(f'No request_id found in reference_id: {reference_id}')
            return 'unknown'

        try:
            response = self.sso_admin.describe_account_assignment_creation_status(
                InstanceArn=self.instance_arn,
                AccountAssignmentCreationRequestId=request_id,
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
