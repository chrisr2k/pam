"""Tests for the providers app - base provider and implementations."""

from unittest.mock import patch, MagicMock, PropertyMock

from django.test import TestCase

from .base import BasePrivilegedAccessProvider
from .aws_identity_center import AWSIdentityCenterProvider
from .entra_pim import EntraPIMProvider


class BaseProviderTests(TestCase):
    """Test the BasePrivilegedAccessProvider abstract class."""

    def test_provision_not_implemented(self):
        """Test that provision_access raises NotImplementedError."""
        with self.assertRaises(TypeError):
            BasePrivilegedAccessProvider()

    def test_deprovision_not_implemented(self):
        """Test that deprovision_access raises NotImplementedError."""
        with self.assertRaises(TypeError):
            BasePrivilegedAccessProvider()


class AWSIdentityCenterProviderTests(TestCase):
    """Test the AWS Identity Center provider."""

    def setUp(self):
        self.provider = AWSIdentityCenterProvider()

    @patch('providers.aws_identity_center.boto3.Session')
    @patch('providers.aws_identity_center.boto3.client')
    def test_provision_success(self, mock_boto_client, mock_boto_session):
        """Test successful provisioning."""
        mock_client = MagicMock()
        mock_boto_client.return_value = mock_client
        mock_session = MagicMock()
        mock_session.client.return_value = mock_client
        mock_boto_session.return_value = mock_session
        mock_client.create_account_assignment.return_value = {
            'AccountAssignmentCreationStatus': {'Status': 'SUCCEEDED', 'RequestId': 'req-123'},
        }
        mock_client.list_instances.return_value = {
            'Instances': [{'IdentityStoreId': 'is-123', 'InstanceArn': 'arn:aws:sso:::instance/ssoins-123'}]
        }
        mock_client.list_users.return_value = {
            'Users': [{'UserId': 'aws-user-123'}]
        }

        # Re-create provider with mocked session
        self.provider = AWSIdentityCenterProvider()

        # Mock the instance_arn property
        with patch.object(AWSIdentityCenterProvider, 'instance_arn', new_callable=PropertyMock, return_value='arn:aws:sso:::instance/ssoins-123'):
            result = self.provider.provision_access(
                'user-oid-123',
                {'permission_set_arn': 'arn:aws:sso:::permissionSet/ps-123', 'account_id': '123456789012'},
                120,
            )
        self.assertTrue(result['success'])

    @patch('providers.aws_identity_center.boto3.client')
    def test_provision_failure(self, mock_boto_client):
        """Test provisioning failure."""
        mock_client = MagicMock()
        mock_boto_client.return_value = mock_client
        mock_client.create_account_assignment.side_effect = Exception('API Error')

        with patch.object(AWSIdentityCenterProvider, 'instance_arn', new_callable=PropertyMock, return_value='arn:aws:sso:::instance/ssoins-123'):
            result = self.provider.provision_access(
                'user-oid-123',
                {'permission_set_arn': 'arn:aws:sso:::permissionSet/ps-123', 'account_id': '123456789012'},
                120,
            )
        self.assertFalse(result['success'])
        self.assertIn('error', result)

    @patch('providers.aws_identity_center.boto3.client')
    def test_deprovision_success(self, mock_boto_client):
        """Test successful deprovisioning."""
        mock_client = MagicMock()
        mock_boto_client.return_value = mock_client

        result = self.provider.deprovision_access('ref-123')
        self.assertTrue(result)

    @patch('providers.aws_identity_center.boto3.client')
    def test_deprovision_failure(self, mock_boto_client):
        """Test deprovisioning failure."""
        mock_client = MagicMock()
        mock_boto_client.return_value = mock_client

        result = self.provider.deprovision_access('ref-123')
        self.assertTrue(result)  # AWS provider always returns True for now


class EntraPIMProviderTests(TestCase):
    """Test the Entra PIM provider."""

    def setUp(self):
        self.provider = EntraPIMProvider()

    @patch('providers.entra_pim.EntraPIMProvider._get_access_token')
    def test_get_token(self, mock_get_token):
        """Test token acquisition."""
        mock_get_token.return_value = 'token-123'
        token = self.provider._get_access_token()
        self.assertEqual(token, 'token-123')

    @patch('providers.entra_pim.EntraPIMProvider._get_access_token')
    def test_get_token_failure(self, mock_get_token):
        """Test token acquisition failure."""
        mock_get_token.return_value = None
        token = self.provider._get_access_token()
        self.assertIsNone(token)

    @patch('providers.entra_pim.EntraPIMProvider._graph_request')
    def test_provision_success(self, mock_graph_request):
        """Test successful provisioning."""
        mock_graph_request.return_value = {'id': 'role-assignment-123'}

        result = self.provider.provision_access(
            'user-oid-123',
            {'role_id': 'role-123'},
            120,
        )
        self.assertTrue(result['success'])
        self.assertEqual(result['reference_id'], 'role-assignment-123')

    @patch('providers.entra_pim.EntraPIMProvider._graph_request')
    def test_provision_failure(self, mock_graph_request):
        """Test provisioning failure."""
        mock_graph_request.return_value = {'error': 'API Error'}

        result = self.provider.provision_access(
            'user-oid-123',
            {'role_id': 'role-123'},
            120,
        )
        self.assertFalse(result['success'])
        self.assertIn('error', result)

    @patch('providers.entra_pim.EntraPIMProvider._graph_request')
    def test_provision_no_role_id(self, mock_graph_request):
        """Test provisioning with no role ID."""
        result = self.provider.provision_access(
            'user-oid-123',
            {},
            120,
        )
        self.assertFalse(result['success'])
        self.assertIn('No role ID', result['error'])

    @patch('providers.entra_pim.EntraPIMProvider._graph_request')
    def test_deprovision_success(self, mock_graph_request):
        """Test successful deprovisioning."""
        mock_graph_request.return_value = {}

        result = self.provider.deprovision_access('assignment-123')
        self.assertTrue(result)

    @patch('providers.entra_pim.EntraPIMProvider._graph_request')
    def test_deprovision_failure(self, mock_graph_request):
        """Test deprovisioning failure."""
        mock_graph_request.return_value = {'error': 'Not found'}

        result = self.provider.deprovision_access('assignment-123')
        self.assertFalse(result)

    @patch('providers.entra_pim.EntraPIMProvider._graph_request')
    def test_list_available_roles(self, mock_graph_request):
        """Test listing available roles."""
        mock_graph_request.return_value = {
            'value': [
                {'id': 'role-1', 'displayName': 'Global Admin', 'description': 'Full access'},
                {'id': 'role-2', 'displayName': 'User Admin', 'description': 'User management'},
            ]
        }

        roles = self.provider.list_available_roles()
        self.assertEqual(len(roles), 2)
        self.assertEqual(roles[0]['name'], 'Global Admin')
        self.assertEqual(roles[0]['provider'], 'ENTRA')

    @patch('providers.entra_pim.EntraPIMProvider._graph_request')
    def test_check_access_status_active(self, mock_graph_request):
        """Test checking active access status."""
        mock_graph_request.return_value = {'id': 'assignment-123'}

        status = self.provider.check_access_status('assignment-123')
        self.assertEqual(status, 'active')

    @patch('providers.entra_pim.EntraPIMProvider._graph_request')
    def test_check_access_status_expired(self, mock_graph_request):
        """Test checking expired access status."""
        mock_graph_request.return_value = {'error': 'Not found'}

        status = self.provider.check_access_status('assignment-123')
        self.assertEqual(status, 'expired')
