"""Tests for the access_requests app - models, views, and workflow."""

from datetime import timedelta
from unittest.mock import patch

from django.test import TestCase, override_settings
from django.contrib.auth import get_user_model
from django.urls import reverse
from django.utils import timezone
from django.contrib.messages import get_messages

from .models import AccessRequest, Approval
from roles.models import PrivilegedRole

User = get_user_model()


class AccessRequestModelTests(TestCase):
    """Test the AccessRequest model."""

    def setUp(self):
        self.requester = User.objects.create_user(
            username='requester', password='testpass',
        )
        self.role = PrivilegedRole.objects.create(
            name='Test-Role',
            provider='AWS',
            aws_permission_set_arn='ps-123',
            max_duration_minutes=240,
        )
        self.request = AccessRequest.objects.create(
            requester=self.requester,
            role=self.role,
            justification='Need access for testing',
            requested_duration_minutes=120,
        )

    def test_request_creation(self):
        """Test basic request creation."""
        self.assertEqual(self.request.requester, self.requester)
        self.assertEqual(self.request.role, self.role)
        self.assertEqual(self.request.status, AccessRequest.Status.PENDING)
        self.assertEqual(self.request.requested_duration_minutes, 120)

    def test_request_str(self):
        """Test string representation."""
        self.assertIn('Test-Role', str(self.request))
        self.assertIn('requester', str(self.request))

    def test_default_status_pending(self):
        """Test default status is PENDING."""
        self.assertEqual(self.request.status, 'PENDING')

    def test_auto_timestamps(self):
        """Test that created_at and updated_at are set."""
        self.assertIsNotNone(self.request.created_at)
        self.assertIsNotNone(self.request.updated_at)

    def test_approvals_relationship(self):
        """Test the approvals reverse relationship."""
        approver = User.objects.create_user(
            username='approver', password='testpass',
        )
        Approval.objects.create(
            request=self.request,
            approver=approver,
            decision=Approval.Decision.APPROVED,
        )
        self.assertEqual(self.request.approvals.count(), 1)

    def test_approve_method(self):
        """Test the approve method."""
        approver = User.objects.create_user(
            username='approver', password='testpass',
        )
        self.request.approve(approver)
        self.assertEqual(self.request.status, AccessRequest.Status.APPROVED)
        self.assertEqual(self.request.approved_by, approver)

    def test_deny_method(self):
        """Test the deny method."""
        approver = User.objects.create_user(
            username='approver', password='testpass',
        )
        self.request.deny(approver, 'Not needed')
        self.assertEqual(self.request.status, AccessRequest.Status.DENIED)
        self.assertEqual(self.request.denial_reason, 'Not needed')

    def test_mark_provisioned(self):
        """Test mark_provisioned."""
        self.request.mark_provisioned(provider_ref='ref-123')
        self.assertEqual(self.request.status, AccessRequest.Status.PROVISIONED)
        self.assertIsNotNone(self.request.provisioned_at)
        self.assertIsNotNone(self.request.expires_at)
        self.assertEqual(self.request.provider_reference_id, 'ref-123')

    def test_mark_failed(self):
        """Test mark_failed."""
        self.request.mark_failed()
        self.assertEqual(self.request.status, AccessRequest.Status.FAILED)

    def test_mark_expired(self):
        """Test mark_expired."""
        self.request.mark_expired()
        self.assertEqual(self.request.status, AccessRequest.Status.EXPIRED)
        self.assertIsNotNone(self.request.deprovisioned_at)


class ApprovalModelTests(TestCase):
    """Test the Approval model."""

    def setUp(self):
        self.requester = User.objects.create_user(
            username='requester', password='testpass',
        )
        self.approver = User.objects.create_user(
            username='approver', password='testpass',
        )
        self.role = PrivilegedRole.objects.create(
            name='Test-Role',
            provider='AWS',
            aws_permission_set_arn='ps-123',
        )
        self.access_request = AccessRequest.objects.create(
            requester=self.requester,
            role=self.role,
            justification='Test',
        )
        self.approval = Approval.objects.create(
            request=self.access_request,
            approver=self.approver,
            decision=Approval.Decision.APPROVED,
            comment='Looks good',
        )

    def test_approval_creation(self):
        """Test basic approval creation."""
        self.assertEqual(self.approval.request, self.access_request)
        self.assertEqual(self.approval.approver, self.approver)
        self.assertEqual(self.approval.decision, 'APPROVED')

    def test_approval_str(self):
        """Test string representation."""
        self.assertIn('approver', str(self.approval))
        self.assertIn('APPROVED', str(self.approval))

    def test_auto_timestamp(self):
        """Test that decided_at is set."""
        self.assertIsNotNone(self.approval.decided_at)

    def test_unique_approver_per_request(self):
        """Test that an approver can only approve once per request."""
        with self.assertRaises(Exception):
            Approval.objects.create(
                request=self.access_request,
                approver=self.approver,
                decision=Approval.Decision.DENIED,
            )


class RequestCreateViewTests(TestCase):
    """Test the request creation view."""

    def setUp(self):
        self.create_url = reverse('requests:create')
        self.requester = User.objects.create_user(
            username='requester', password='testpass',
        )
        self.role = PrivilegedRole.objects.create(
            name='Test-Role',
            provider='AWS',
            aws_permission_set_arn='ps-123',
            max_duration_minutes=240,
        )

    def test_create_requires_login(self):
        """Test that create requires authentication."""
        response = self.client.get(self.create_url)
        self.assertEqual(response.status_code, 302)

    def test_create_page_loads(self):
        """Test that create page loads."""
        self.client.force_login(self.requester)
        response = self.client.get(self.create_url)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'pam/request_form.html')

    def test_create_submission(self):
        """Test creating a new request."""
        self.client.force_login(self.requester)
        response = self.client.post(self.create_url, {
            'role': self.role.pk,
            'justification': 'Need access',
            'requested_duration_minutes': 120,
        })
        self.assertEqual(AccessRequest.objects.count(), 1)
        request_obj = AccessRequest.objects.first()
        self.assertRedirects(response, reverse(
            'requests:detail', kwargs={'pk': request_obj.pk},
        ))

    def test_create_without_justification(self):
        """Test that justification is required."""
        self.client.force_login(self.requester)
        response = self.client.post(self.create_url, {
            'role': self.role.pk,
            'requested_duration_minutes': 120,
        })
        self.assertEqual(response.status_code, 200)  # Form error, re-renders
        self.assertEqual(AccessRequest.objects.count(), 0)


class RequestListViewTests(TestCase):
    """Test the request list views."""

    def setUp(self):
        self.requester = User.objects.create_user(
            username='requester', password='testpass',
        )
        self.approver = User.objects.create_user(
            username='approver', password='testpass',
            role=User.Role.APPROVER,
        )
        self.role = PrivilegedRole.objects.create(
            name='Test-Role',
            provider='AWS',
            aws_permission_set_arn='ps-123',
        )
        # Add approver to the role's approvers
        self.role.approvers.add(self.approver)

    def test_my_requests_shows_own(self):
        """Test my_requests shows only own requests."""
        self.client.force_login(self.requester)
        AccessRequest.objects.create(
            requester=self.requester, role=self.role, justification='Mine',
        )
        AccessRequest.objects.create(
            requester=self.approver, role=self.role, justification='Not mine',
        )
        response = self.client.get(reverse('requests:my_requests'))
        self.assertEqual(len(response.context['requests']), 1)

    def test_pending_approvals_shows_others(self):
        """Test pending_approvals shows requests needing approval."""
        self.client.force_login(self.approver)
        AccessRequest.objects.create(
            requester=self.requester, role=self.role, justification='Needs approval',
        )
        response = self.client.get(reverse('requests:pending_approvals'))
        self.assertEqual(len(response.context['requests']), 1)

    def test_pending_approvals_shows_own(self):
        """Test pending_approvals shows own requests if user is an approver for the role."""
        self.client.force_login(self.approver)
        AccessRequest.objects.create(
            requester=self.approver, role=self.role, justification='Mine',
        )
        response = self.client.get(reverse('requests:pending_approvals'))
        self.assertEqual(len(response.context['requests']), 1)


class ApprovalActionViewTests(TestCase):
    """Test the approval action view."""

    def setUp(self):
        self.requester = User.objects.create_user(
            username='requester', password='testpass',
        )
        self.approver = User.objects.create_user(
            username='approver', password='testpass',
            role=User.Role.APPROVER,
        )
        self.role = PrivilegedRole.objects.create(
            name='Test-Role',
            provider='AWS',
            aws_permission_set_arn='ps-123',
        )
        # Add approver to the role's approvers
        self.role.approvers.add(self.approver)
        self.access_request = AccessRequest.objects.create(
            requester=self.requester,
            role=self.role,
            justification='Test',
        )

    def test_approve_requires_login(self):
        """Test that approve requires authentication."""
        url = reverse('requests:approve', kwargs={'pk': self.access_request.pk})
        response = self.client.post(url)
        self.assertEqual(response.status_code, 302)

    def test_approve_requires_approver_role(self):
        """Test that approve requires approver role."""
        self.client.force_login(self.requester)
        url = reverse('requests:approve', kwargs={'pk': self.access_request.pk})
        response = self.client.post(url)
        self.assertEqual(response.status_code, 403)

    @patch('tasks.provisioning.provision_access_sync')
    def test_approve_creates_approval(self, mock_provision):
        """Test that approve creates an approval record."""
        self.client.force_login(self.approver)
        url = reverse('requests:approve', kwargs={'pk': self.access_request.pk})
        response = self.client.post(url, {'comment': 'Approved'})
        self.assertEqual(Approval.objects.count(), 1)
        approval = Approval.objects.first()
        self.assertEqual(approval.decision, Approval.Decision.APPROVED)

    @patch('tasks.provisioning.provision_access_sync')
    def test_deny_creates_approval(self, mock_provision):
        """Test that deny creates an approval record."""
        self.client.force_login(self.approver)
        url = reverse('requests:deny', kwargs={'pk': self.access_request.pk})
        response = self.client.post(url, {'comment': 'Denied'})
        self.assertEqual(Approval.objects.count(), 1)
        approval = Approval.objects.first()
        self.assertEqual(approval.decision, Approval.Decision.DENIED)

    @patch('tasks.provisioning.provision_access_sync')
    def test_approve_updates_request_status(self, mock_provision):
        """Test that approve updates request status to APPROVED."""
        self.client.force_login(self.approver)
        url = reverse('requests:approve', kwargs={'pk': self.access_request.pk})
        self.client.post(url, {'comment': 'Approved'})
        self.access_request.refresh_from_db()
        self.assertEqual(self.access_request.status, AccessRequest.Status.APPROVED)

    @patch('tasks.provisioning.provision_access_sync')
    def test_deny_updates_request_status(self, mock_provision):
        """Test that deny updates request status to DENIED."""
        self.client.force_login(self.approver)
        url = reverse('requests:deny', kwargs={'pk': self.access_request.pk})
        self.client.post(url, {'comment': 'Denied'})
        self.access_request.refresh_from_db()
        self.assertEqual(self.access_request.status, AccessRequest.Status.DENIED)


class DashboardViewTests(TestCase):
    """Test the dashboard view."""

    def setUp(self):
        self.dashboard_url = reverse('requests:dashboard')
        self.user = User.objects.create_user(username='testuser', password='testpass')

    def test_dashboard_requires_login(self):
        """Test that dashboard requires authentication."""
        response = self.client.get(self.dashboard_url)
        self.assertEqual(response.status_code, 302)

    def test_dashboard_loads(self):
        """Test that dashboard loads."""
        self.client.force_login(self.user)
        response = self.client.get(self.dashboard_url)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'pam/dashboard.html')


class ActiveSessionsViewTests(TestCase):
    """Test the active sessions view."""

    def setUp(self):
        self.sessions_url = reverse('requests:active_sessions')
        self.admin = User.objects.create_user(
            username='admin', password='adminpass',
            role=User.Role.ADMIN,
        )
        self.user = User.objects.create_user(username='user', password='testpass')

    def test_sessions_requires_admin(self):
        """Test that sessions requires admin."""
        self.client.force_login(self.user)
        response = self.client.get(self.sessions_url)
        # UserPassesTestMixin returns 403 for non-admin users
        self.assertEqual(response.status_code, 403)

    def test_sessions_loads_for_admin(self):
        """Test that sessions loads for admin."""
        self.client.force_login(self.admin)
        response = self.client.get(self.sessions_url)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'pam/active_sessions.html')


class RevokeViewTests(TestCase):
    """Test the revoke view."""

    def setUp(self):
        self.requester = User.objects.create_user(
            username='requester', password='testpass',
        )
        self.role = PrivilegedRole.objects.create(
            name='Test-Role',
            provider='AWS',
            aws_permission_set_arn='ps-123',
        )
        self.access_request = AccessRequest.objects.create(
            requester=self.requester,
            role=self.role,
            justification='Test',
            status=AccessRequest.Status.PROVISIONED,
            provisioned_at=timezone.now(),
            expires_at=timezone.now() + timedelta(hours=2),
        )

    @patch('tasks.provisioning.deprovision_access_sync')
    def test_revoke_own_request(self, mock_deprovision):
        """Test that user can revoke their own request."""
        # Mock the deprovision function to just mark as expired
        def mock_deprovision_func(request_id):
            from access_requests.models import AccessRequest
            req = AccessRequest.objects.get(id=request_id)
            req.mark_expired()

        mock_deprovision.side_effect = mock_deprovision_func

        self.client.force_login(self.requester)
        url = reverse('requests:revoke', kwargs={'pk': self.access_request.pk})
        response = self.client.post(url)
        self.access_request.refresh_from_db()
        # deprovision_access_sync sets status to EXPIRED
        self.assertEqual(self.access_request.status, AccessRequest.Status.EXPIRED)

    def test_revoke_requires_login(self):
        """Test that revoke requires authentication."""
        url = reverse('requests:revoke', kwargs={'pk': self.access_request.pk})
        response = self.client.post(url)
        self.assertEqual(response.status_code, 302)

    def test_revoke_other_user_request(self):
        """Test that user cannot revoke another's request (returns 404)."""
        other = User.objects.create_user(username='other', password='testpass')
        self.client.force_login(other)
        url = reverse('requests:revoke', kwargs={'pk': self.access_request.pk})
        response = self.client.post(url)
        # RevokeAccessView filters by requester=request.user, so returns 404
        self.assertEqual(response.status_code, 404)


class PollViewTests(TestCase):
    """Test the polling view for live updates."""

    def setUp(self):
        self.poll_url = reverse('requests:poll')
        self.user = User.objects.create_user(username='testuser', password='testpass')

    def test_poll_requires_login(self):
        """Test that poll requires authentication."""
        response = self.client.get(self.poll_url)
        self.assertEqual(response.status_code, 302)

    def test_poll_returns_json(self):
        """Test that poll returns JSON."""
        self.client.force_login(self.user)
        response = self.client.get(self.poll_url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'application/json')
