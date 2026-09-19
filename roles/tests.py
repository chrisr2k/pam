"""Tests for the roles app - models and views."""

from django.test import TestCase
from django.contrib.auth import get_user_model
from django.urls import reverse

from .models import PrivilegedRole

User = get_user_model()


class PrivilegedRoleModelTests(TestCase):
    """Test the PrivilegedRole model."""

    def setUp(self):
        self.role = PrivilegedRole.objects.create(
            name='AWS-Admin',
            description='Full AWS admin access',
            provider='AWS',
            aws_permission_set_arn='arn:aws:sso:::permissionSet/ps-123',
            aws_account_id='123456789012',
            max_duration_minutes=240,
        )

    def test_role_creation(self):
        """Test basic role creation."""
        self.assertEqual(self.role.name, 'AWS-Admin')
        self.assertEqual(self.role.provider, 'AWS')
        self.assertEqual(self.role.max_duration_minutes, 240)

    def test_role_str_aws(self):
        """Test string representation for AWS role."""
        self.assertIn('AWS', str(self.role))
        self.assertIn('AWS-Admin', str(self.role))

    def test_role_str_entra(self):
        """Test string representation for Entra role."""
        role2 = PrivilegedRole.objects.create(
            name='Entra-Admin',
            provider='ENTRA',
            entra_role_id='role-123',
        )
        self.assertIn('Entra', str(role2))
        self.assertIn('Entra-Admin', str(role2))

    def test_default_max_duration(self):
        """Test default max duration."""
        role2 = PrivilegedRole.objects.create(
            name='Test-Role',
            provider='ENTRA',
            entra_role_id='role-456',
        )
        self.assertEqual(role2.max_duration_minutes, 480)

    def test_unique_aws_role(self):
        """Test that AWS role must be unique per permission set + account."""
        with self.assertRaises(Exception):
            PrivilegedRole.objects.create(
                name='AWS-Admin-Duplicate',
                provider='AWS',
                aws_permission_set_arn='arn:aws:sso:::permissionSet/ps-123',
                aws_account_id='123456789012',
            )

    def test_same_arn_different_account(self):
        """Test that same ARN is allowed for different accounts."""
        role2 = PrivilegedRole.objects.create(
            name='AWS-Admin-Other',
            provider='AWS',
            aws_permission_set_arn='arn:aws:sso:::permissionSet/ps-123',
            aws_account_id='999999999999',
        )
        self.assertIsNotNone(role2.pk)

    def test_default_requires_approval(self):
        """Test default requires_approval is True."""
        self.assertTrue(self.role.requires_approval)

    def test_default_is_active(self):
        """Test default is_active is True."""
        self.assertTrue(self.role.is_active)


class PrivilegedRoleQuorumTests(TestCase):
    """Test the per-role approval quorum fields."""

    def setUp(self):
        self.approvers = [
            User.objects.create_user(username=f'approver{i}', password='testpass')
            for i in range(3)
        ]

    def _make_role(self, policy, quorum_count=1):
        role = PrivilegedRole.objects.create(
            name=f'Role-{policy}',
            provider='AWS',
            aws_permission_set_arn=f'ps-{policy}',
            approval_policy=policy,
            quorum_count=quorum_count,
        )
        role.approvers.add(*self.approvers)
        return role

    def test_default_approval_policy_is_any_one(self):
        """New roles default to ANY_ONE with quorum_count 1."""
        role = PrivilegedRole.objects.create(
            name='Default-Role',
            provider='AWS',
            aws_permission_set_arn='ps-default',
        )
        self.assertEqual(role.approval_policy, PrivilegedRole.ApprovalPolicy.ANY_ONE)
        self.assertEqual(role.quorum_count, 1)

    def test_quorum_count_validation_rejects_zero(self):
        """quorum_count below 1 is rejected by clean()."""
        role = PrivilegedRole(
            name='Bad-Quorum',
            provider='AWS',
            aws_permission_set_arn='ps-bad-quorum',
            quorum_count=0,
        )
        from django.core.exceptions import ValidationError
        with self.assertRaises(ValidationError):
            role.full_clean()

    def test_approval_threshold_per_policy(self):
        """ANY_ONE→1, ALL→approver count, QUORUM→quorum_count."""
        self.assertEqual(
            self._make_role(PrivilegedRole.ApprovalPolicy.ANY_ONE).approval_threshold(), 1)
        self.assertEqual(
            self._make_role(PrivilegedRole.ApprovalPolicy.ALL).approval_threshold(), 3)
        self.assertEqual(
            self._make_role(PrivilegedRole.ApprovalPolicy.QUORUM, quorum_count=2)
            .approval_threshold(), 2)

    def test_approval_threshold_caps_at_approver_count(self):
        """A QUORUM above the approver count is capped at the approver count."""
        role = self._make_role(PrivilegedRole.ApprovalPolicy.QUORUM, quorum_count=5)
        self.assertEqual(role.approval_threshold(), 3)


class PrivilegedRoleVaultTests(TestCase):
    """Test the VAULT provider linkage."""

    def setUp(self):
        from vault.models import VaultEntry
        self.entry = VaultEntry.objects.create(
            name='Prod-DB', secret_type='PASSWORD', encrypted_value='pw')
        # The post_save signal auto-creates the shim role
        self.shim = self.entry.shim_role

    def test_shim_role_passes_full_clean(self):
        """The auto-created VAULT shim role is valid."""
        self.shim.full_clean()  # should not raise
        self.assertEqual(self.shim.provider, PrivilegedRole.Provider.VAULT)

    def test_vault_role_requires_entry(self):
        """A VAULT role without an entry fails validation."""
        from django.core.exceptions import ValidationError
        role = PrivilegedRole(
            name='Bad-Vault-Role',
            provider=PrivilegedRole.Provider.VAULT,
        )
        with self.assertRaises(ValidationError):
            role.full_clean()

    def test_one_shim_per_entry(self):
        """A second VAULT role for the same entry violates the OneToOne."""
        with self.assertRaises(Exception):
            PrivilegedRole.objects.create(
                name='Vault: Prod-DB Duplicate',
                provider=PrivilegedRole.Provider.VAULT,
                vault_entry=self.entry,
            )


class RoleListViewTests(TestCase):
    """Test the role list view."""

    def setUp(self):
        self.list_url = reverse('roles:list')
        self.user = User.objects.create_user(username='testuser', password='testpass')
        PrivilegedRole.objects.create(
            name='Role-1',
            provider='AWS',
            aws_permission_set_arn='ps-1',
        )
        PrivilegedRole.objects.create(
            name='Role-2',
            provider='ENTRA',
            entra_role_id='role-2',
        )

    def test_list_requires_login(self):
        """Test that list requires authentication."""
        response = self.client.get(self.list_url)
        self.assertEqual(response.status_code, 302)

    def test_list_shows_active_roles(self):
        """Test that list shows only active roles."""
        self.client.force_login(self.user)
        response = self.client.get(self.list_url)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'pam/role_list.html')
        self.assertEqual(len(response.context['roles']), 2)

    def test_list_excludes_inactive_roles(self):
        """Test that inactive roles are excluded."""
        PrivilegedRole.objects.create(
            name='Inactive-Role',
            provider='AWS',
            aws_permission_set_arn='ps-inactive',
            is_active=False,
        )
        self.client.force_login(self.user)
        response = self.client.get(self.list_url)
        self.assertEqual(len(response.context['roles']), 2)


class RoleDetailViewTests(TestCase):
    """Test the role detail view."""

    def setUp(self):
        self.role = PrivilegedRole.objects.create(
            name='Test-Role',
            provider='AWS',
            aws_permission_set_arn='ps-123',
            description='A test role',
        )
        self.detail_url = reverse('roles:detail', kwargs={'pk': self.role.pk})
        self.user = User.objects.create_user(username='testuser', password='testpass')

    def test_detail_requires_login(self):
        """Test that detail requires authentication."""
        response = self.client.get(self.detail_url)
        self.assertEqual(response.status_code, 302)

    def test_detail_shows_role(self):
        """Test that detail shows role info."""
        self.client.force_login(self.user)
        response = self.client.get(self.detail_url)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'pam/role_detail.html')
        self.assertEqual(response.context['role'], self.role)

    def test_detail_404(self):
        """Test that non-existent role returns 404."""
        self.client.force_login(self.user)
        response = self.client.get(reverse('roles:detail', kwargs={'pk': 99999}))
        self.assertEqual(response.status_code, 404)
