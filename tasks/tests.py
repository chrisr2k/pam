"""Tests for the tasks app - provisioning tasks and management commands."""

from datetime import timedelta
from unittest.mock import patch, MagicMock

from django.test import TestCase
from django.contrib.auth import get_user_model
from django.utils import timezone
from django.core.management import call_command

from .provisioning import provision_access_sync, deprovision_access_sync
from roles.models import PrivilegedRole
from access_requests.models import AccessRequest

User = get_user_model()


class ProvisionAccessSyncTests(TestCase):
    """Test the synchronous provisioning function."""

    def setUp(self):
        self.requester = User.objects.create_user(
            username='requester',
            email='requester@example.com',
            entra_object_id='oid-requester',
        )
        self.role = PrivilegedRole.objects.create(
            name='Test-Role',
            provider='AWS',
            aws_permission_set_arn='ps-123',
            aws_account_id='123456789012',
            max_duration_minutes=240,
        )
        self.access_request = AccessRequest.objects.create(
            requester=self.requester,
            role=self.role,
            justification='Test',
            requested_duration_minutes=120,
        )

    @patch('providers.aws_identity_center.AWSIdentityCenterProvider')
    def test_provision_success(self, mock_provider_cls):
        """Test successful provisioning."""
        mock_provider = MagicMock()
        mock_provider_cls.return_value = mock_provider
        mock_provider.provision_access.return_value = {
            'success': True,
            'reference_id': 'ref-123',
        }

        # First approve the request
        self.access_request.approve(self.requester)

        result = provision_access_sync(self.access_request.pk)
        self.assertIsNone(result)  # Function returns None on success
        self.access_request.refresh_from_db()
        self.assertEqual(self.access_request.status, AccessRequest.Status.PROVISIONED)
        self.assertIsNotNone(self.access_request.provisioned_at)
        self.assertIsNotNone(self.access_request.expires_at)

    @patch('providers.aws_identity_center.AWSIdentityCenterProvider')
    def test_provision_failure(self, mock_provider_cls):
        """Test provisioning failure."""
        mock_provider = MagicMock()
        mock_provider_cls.return_value = mock_provider
        mock_provider.provision_access.return_value = {
            'success': False,
            'error': 'API Error',
        }

        # First approve the request
        self.access_request.approve(self.requester)

        result = provision_access_sync(self.access_request.pk)
        self.assertIsNone(result)
        self.access_request.refresh_from_db()
        self.assertEqual(self.access_request.status, AccessRequest.Status.FAILED)

    def test_provision_nonexistent_request(self):
        """Test provisioning with non-existent request."""
        result = provision_access_sync(99999)
        self.assertIsNone(result)

    def test_provision_not_approved(self):
        """Test provisioning a non-approved request."""
        result = provision_access_sync(self.access_request.pk)
        self.assertIsNone(result)
        self.access_request.refresh_from_db()
        self.assertEqual(self.access_request.status, AccessRequest.Status.PENDING)

    def test_provision_no_entra_oid(self):
        """Test provisioning with no Entra OID."""
        self.requester.entra_object_id = None
        self.requester.save()
        self.access_request.approve(self.requester)
        result = provision_access_sync(self.access_request.pk)
        self.assertIsNone(result)
        self.access_request.refresh_from_db()
        self.assertEqual(self.access_request.status, AccessRequest.Status.FAILED)


class DeprovisionAccessSyncTests(TestCase):
    """Test the synchronous deprovisioning function."""

    def setUp(self):
        self.requester = User.objects.create_user(
            username='requester',
            email='requester@example.com',
            entra_object_id='oid-requester',
        )
        self.role = PrivilegedRole.objects.create(
            name='Test-Role',
            provider='AWS',
            aws_permission_set_arn='ps-123',
            aws_account_id='123456789012',
        )
        self.access_request = AccessRequest.objects.create(
            requester=self.requester,
            role=self.role,
            justification='Test',
            status=AccessRequest.Status.PROVISIONED,
            provisioned_at=timezone.now(),
            expires_at=timezone.now() + timedelta(hours=2),
            provider_reference_id='ref-123',
        )

    @patch('providers.aws_identity_center.AWSIdentityCenterProvider')
    def test_deprovision_success(self, mock_provider_cls):
        """Test successful deprovisioning."""
        mock_provider = MagicMock()
        mock_provider_cls.return_value = mock_provider
        mock_provider.deprovision_access.return_value = True

        result = deprovision_access_sync(self.access_request.pk)
        self.assertIsNone(result)
        self.access_request.refresh_from_db()
        self.assertEqual(self.access_request.status, AccessRequest.Status.EXPIRED)

    @patch('providers.aws_identity_center.AWSIdentityCenterProvider')
    def test_deprovision_failure(self, mock_provider_cls):
        """Test deprovisioning failure."""
        mock_provider = MagicMock()
        mock_provider_cls.return_value = mock_provider
        mock_provider.deprovision_access.return_value = False

        result = deprovision_access_sync(self.access_request.pk)
        self.assertIsNone(result)
        self.access_request.refresh_from_db()
        self.assertEqual(self.access_request.status, AccessRequest.Status.PROVISIONED)

    def test_deprovision_nonexistent_request(self):
        """Test deprovisioning with non-existent request."""
        result = deprovision_access_sync(99999)
        self.assertIsNone(result)

    def test_deprovision_no_reference_id(self):
        """Test deprovisioning with no reference ID."""
        self.access_request.provider_reference_id = ''
        self.access_request.save()
        result = deprovision_access_sync(self.access_request.pk)
        self.assertIsNone(result)
        self.access_request.refresh_from_db()
        self.assertEqual(self.access_request.status, AccessRequest.Status.EXPIRED)

    def test_deprovision_not_provisioned(self):
        """Test deprovisioning a non-provisioned request."""
        self.access_request.status = AccessRequest.Status.PENDING
        self.access_request.save()
        result = deprovision_access_sync(self.access_request.pk)
        self.assertIsNone(result)
        self.access_request.refresh_from_db()
        self.assertEqual(self.access_request.status, AccessRequest.Status.PENDING)


class CheckExpiredCommandTests(TestCase):
    """Test the check_expired management command."""

    def setUp(self):
        self.requester = User.objects.create_user(
            username='requester',
            email='requester@example.com',
            entra_object_id='oid-requester',
        )
        self.role = PrivilegedRole.objects.create(
            name='Test-Role',
            provider='AWS',
            aws_permission_set_arn='ps-123',
            aws_account_id='123456789012',
        )

    @patch('tasks.management.commands.check_expired.deprovision_access_sync')
    def test_expired_session_deprovisioned(self, mock_deprovision):
        """Test that expired sessions are deprovisioned."""
        mock_deprovision.return_value = None
        AccessRequest.objects.create(
            requester=self.requester,
            role=self.role,
            justification='Expired',
            status=AccessRequest.Status.PROVISIONED,
            provisioned_at=timezone.now() - timedelta(hours=4),
            expires_at=timezone.now() - timedelta(hours=1),
            provider_reference_id='ref-123',
        )
        call_command('check_expired')
        self.assertEqual(mock_deprovision.call_count, 1)

    @patch('tasks.management.commands.check_expired.deprovision_access_sync')
    def test_active_session_not_deprovisioned(self, mock_deprovision):
        """Test that active (non-expired) sessions are not deprovisioned."""
        mock_deprovision.return_value = None
        AccessRequest.objects.create(
            requester=self.requester,
            role=self.role,
            justification='Active',
            status=AccessRequest.Status.PROVISIONED,
            provisioned_at=timezone.now(),
            expires_at=timezone.now() + timedelta(hours=2),
            provider_reference_id='ref-456',
        )
        call_command('check_expired')
        self.assertEqual(mock_deprovision.call_count, 0)

    @patch('tasks.management.commands.check_expired.deprovision_access_sync')
    def test_non_approved_not_deprovisioned(self, mock_deprovision):
        """Test that non-approved requests are not deprovisioned."""
        mock_deprovision.return_value = None
        AccessRequest.objects.create(
            requester=self.requester,
            role=self.role,
            justification='Pending',
            status=AccessRequest.Status.PENDING,
        )
        call_command('check_expired')
        self.assertEqual(mock_deprovision.call_count, 0)
