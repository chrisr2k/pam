"""Tests for the access_requests app - models, views, and workflow."""

from datetime import timedelta
from unittest.mock import patch

import pyotp
from django.test import TestCase, override_settings
from django.contrib.auth import get_user_model
from django.urls import reverse
from django.utils import timezone
from django.contrib.messages import get_messages

from .forms import AccessRequestForm
from .models import AccessRequest, Approval
from .services import execute_approve
from audit.models import AuditLog
from roles.models import PrivilegedRole

User = get_user_model()

# RFC 6238 test-vector secret, used to enroll users in MFA for view tests
OTP_SECRET = 'JBSWY3DPEHPK3PXP'


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
    """Test the approval action view.

    Approvers are MFA-enrolled (their role requires it), so approval is a
    two-step flow: the approve POST renders the challenge page, then the
    challenge POST with a valid TOTP code executes the approval.
    """

    def setUp(self):
        self.requester = User.objects.create_user(
            username='requester', password='testpass',
        )
        self.approver = User.objects.create_user(
            username='approver', password='testpass',
            role=User.Role.APPROVER,
        )
        # Enroll the approver in MFA (required before approving)
        self.approver.set_otp_secret(OTP_SECRET)
        self.approver.mfa_enrolled_at = timezone.now()
        self.approver.save()
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

    def _approve_via_challenge(self, comment='Approved'):
        """Drive the two-step approval flow and return the final response."""
        url = reverse('requests:approve', kwargs={'pk': self.access_request.pk})
        response = self.client.post(url, {'comment': comment})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'pam/mfa_challenge.html')
        ticket = self.client.session['mfa_ticket']
        code = pyotp.TOTP(OTP_SECRET).now()
        return self.client.post(reverse('accounts:mfa_challenge'), {
            'code': code,
            'comment': comment,
            'ticket': ticket,
            'target_id': str(self.access_request.pk),
        })

    def test_approve_requires_login(self):
        """Test that approve requires authentication."""
        url = reverse('requests:approve', kwargs={'pk': self.access_request.pk})
        response = self.client.post(url)
        self.assertEqual(response.status_code, 302)

    def test_approve_non_member_rejected(self):
        """A user who is not a role approver is rejected with an error."""
        self.client.force_login(self.requester)
        url = reverse('requests:approve', kwargs={'pk': self.access_request.pk})
        response = self.client.post(url)
        self.assertRedirects(response, reverse(
            'requests:detail', kwargs={'pk': self.access_request.pk}))
        self.access_request.refresh_from_db()
        self.assertEqual(self.access_request.status, AccessRequest.Status.PENDING)
        self.assertEqual(Approval.objects.count(), 0)

    @patch('tasks.provisioning.provision_access_sync')
    def test_approve_creates_approval(self, mock_provision):
        """Test that approve creates an approval record."""
        self.client.force_login(self.approver)
        self._approve_via_challenge()
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
        self._approve_via_challenge()
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
        def mock_deprovision_func(request_id, trigger='expired'):
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


class QuorumApprovalTests(TestCase):
    """Test per-role approval quorum (QUORUM/ALL policies)."""

    def setUp(self):
        self.requester = User.objects.create_user(
            username='requester', password='testpass',
        )
        self.approvers = []
        for name in ('approver_a', 'approver_b', 'approver_c'):
            user = User.objects.create_user(
                username=name, password='testpass', role=User.Role.APPROVER)
            # Enroll in MFA (approvers are required to be enrolled)
            user.set_otp_secret(OTP_SECRET)
            user.mfa_enrolled_at = timezone.now()
            user.save()
            self.approvers.append(user)
        self.role = PrivilegedRole.objects.create(
            name='Quorum-Role',
            provider='AWS',
            aws_permission_set_arn='ps-quorum',
            approval_policy=PrivilegedRole.ApprovalPolicy.QUORUM,
            quorum_count=2,
        )
        self.role.approvers.add(*self.approvers)
        self.access_request = AccessRequest.objects.create(
            requester=self.requester,
            role=self.role,
            justification='Test',
        )

    def _vote_via_challenge(self, approver, comment='Approved'):
        """Drive the two-step approve flow for a given approver."""
        self.client.force_login(approver)
        url = reverse('requests:approve', kwargs={'pk': self.access_request.pk})
        response = self.client.post(url, {'comment': comment})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'pam/mfa_challenge.html')
        ticket = self.client.session['mfa_ticket']
        code = pyotp.TOTP(OTP_SECRET).now()
        return self.client.post(reverse('accounts:mfa_challenge'), {
            'code': code,
            'comment': comment,
            'ticket': ticket,
            'target_id': str(self.access_request.pk),
        })

    @patch('tasks.provisioning.provision_access_sync')
    def test_quorum_first_vote_stays_pending(self, mock_provision):
        """The first vote is recorded; the request stays PENDING."""
        response = self._vote_via_challenge(self.approvers[0])
        self.assertRedirects(response, reverse(
            'requests:detail', kwargs={'pk': self.access_request.pk}))
        self.access_request.refresh_from_db()
        self.assertEqual(self.access_request.status, AccessRequest.Status.PENDING)
        self.assertEqual(Approval.objects.count(), 1)
        self.assertTrue(AuditLog.objects.filter(action='APPROVAL_RECORDED').exists())
        self.assertFalse(AuditLog.objects.filter(action='REQUEST_APPROVED').exists())
        mock_provision.assert_not_called()

    @patch('tasks.provisioning.provision_access_sync')
    def test_quorum_second_vote_completes(self, mock_provision):
        """The second distinct vote meets quorum and finalizes."""
        self._vote_via_challenge(self.approvers[0])
        self._vote_via_challenge(self.approvers[1])
        self.access_request.refresh_from_db()
        self.assertEqual(self.access_request.status, AccessRequest.Status.APPROVED)
        self.assertEqual(self.access_request.approved_by, self.approvers[1])
        self.assertEqual(Approval.objects.count(), 2)
        self.assertTrue(AuditLog.objects.filter(action='REQUEST_APPROVED').exists())
        mock_provision.assert_called_once()

    @patch('tasks.provisioning.provision_access_sync')
    def test_all_policy_requires_every_approver(self, mock_provision):
        """ALL policy: every approver must vote."""
        self.role.approval_policy = PrivilegedRole.ApprovalPolicy.ALL
        self.role.save()
        self._vote_via_challenge(self.approvers[0])
        self._vote_via_challenge(self.approvers[1])
        self.access_request.refresh_from_db()
        self.assertEqual(self.access_request.status, AccessRequest.Status.PENDING)
        self._vote_via_challenge(self.approvers[2])
        self.access_request.refresh_from_db()
        self.assertEqual(self.access_request.status, AccessRequest.Status.APPROVED)

    def test_deny_still_denies_immediately(self):
        """Any approver can still deny the whole request immediately."""
        self._vote_via_challenge(self.approvers[0])
        self.client.force_login(self.approvers[1])
        url = reverse('requests:deny', kwargs={'pk': self.access_request.pk})
        self.client.post(url, {'reason': 'Not needed'})
        self.access_request.refresh_from_db()
        self.assertEqual(self.access_request.status, AccessRequest.Status.DENIED)
        self.assertEqual(Approval.objects.count(), 2)

    def test_duplicate_vote_is_graceful(self):
        """A second vote by the same approver is handled, never a 500."""
        self._vote_via_challenge(self.approvers[0])
        # Repeat approve POST: pre-check redirects with an info message,
        # no challenge page, and no new Approval row.
        self.client.force_login(self.approvers[0])
        url = reverse('requests:approve', kwargs={'pk': self.access_request.pk})
        response = self.client.post(url, {'comment': 'Again'})
        self.assertRedirects(response, reverse(
            'requests:detail', kwargs={'pk': self.access_request.pk}))
        self.assertEqual(Approval.objects.count(), 1)
        messages = [str(m) for m in get_messages(response.wsgi_request)]
        self.assertTrue(any('already approved' in m for m in messages))
        # Direct service call covers the challenge-revalidation path
        ok, err, outcome = execute_approve(self.approvers[0], self.access_request.pk)
        self.assertTrue(ok)
        self.assertEqual(outcome, 'duplicate_vote')

    @patch('access_requests.services.send_notification')
    def test_notification_only_on_final_approval(self, mock_notify):
        """The requester is notified only when quorum is met."""
        self._vote_via_challenge(self.approvers[0])
        mock_notify.assert_not_called()
        self._vote_via_challenge(self.approvers[1])
        mock_notify.assert_called_once()
        self.assertEqual(mock_notify.call_args.args[1], 'request_approved')

    def test_detail_page_progress_and_you_approved(self):
        """The detail page shows vote progress and per-approver state."""
        self._vote_via_challenge(self.approvers[0])
        detail_url = reverse('requests:detail', kwargs={'pk': self.access_request.pk})
        self.client.force_login(self.approvers[1])
        response = self.client.get(detail_url)
        self.assertContains(response, '1 of 2 approved')
        self.client.force_login(self.approvers[0])
        response = self.client.get(detail_url)
        self.assertContains(response, 'You approved this request')


class AutoApproveTests(TestCase):
    """Test requires_approval=False roles auto-approve on submission."""

    def setUp(self):
        self.create_url = reverse('requests:create')
        self.requester = User.objects.create_user(
            username='requester', password='testpass',
        )
        self.role = PrivilegedRole.objects.create(
            name='No-Approval-Role',
            provider='AWS',
            aws_permission_set_arn='ps-no-approval',
            requires_approval=False,
        )

    @patch('tasks.provisioning.provision_access_sync')
    def test_no_approval_role_creates_approved_directly(self, mock_provision):
        """Submission creates the request APPROVED and provisions immediately."""
        self.client.force_login(self.requester)
        response = self.client.post(self.create_url, {
            'role': self.role.pk,
            'justification': 'Need access',
            'requested_duration_minutes': '60',
        })
        self.assertEqual(AccessRequest.objects.count(), 1)
        req = AccessRequest.objects.first()
        self.assertRedirects(response, reverse('requests:detail', kwargs={'pk': req.pk}))
        self.assertEqual(req.status, AccessRequest.Status.APPROVED)
        self.assertEqual(req.approved_by, self.requester)
        self.assertIsNotNone(req.approved_at)
        audit = AuditLog.objects.filter(action='REQUEST_CREATED').first()
        self.assertIsNotNone(audit)
        self.assertTrue(audit.details.get('auto'))
        mock_provision.assert_called_once()

    @patch('access_requests.services.send_notification')
    @patch('tasks.provisioning.provision_access_sync')
    def test_no_approval_role_skips_approver_notifications(self, mock_provision, mock_notify):
        """No approver notifications are sent for auto-approved requests."""
        self.client.force_login(self.requester)
        self.client.post(self.create_url, {
            'role': self.role.pk,
            'justification': 'Need access',
            'requested_duration_minutes': '60',
        })
        mock_notify.assert_not_called()

    @patch('tasks.provisioning.provision_access_sync')
    def test_no_approval_role_via_mfa_challenge(self, mock_provision):
        """An enrolled requester auto-approves after the MFA challenge."""
        self.requester.set_otp_secret(OTP_SECRET)
        self.requester.mfa_enrolled_at = timezone.now()
        self.requester.save()
        self.client.force_login(self.requester)
        response = self.client.post(self.create_url, {
            'role': self.role.pk,
            'justification': 'Need access',
            'requested_duration_minutes': '60',
        })
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'pam/mfa_challenge.html')
        self.assertEqual(AccessRequest.objects.count(), 0)
        ticket = self.client.session['mfa_ticket']
        response = self.client.post(reverse('accounts:mfa_challenge'), {
            'code': pyotp.TOTP(OTP_SECRET).now(),
            'ticket': ticket,
            'target_id': '',
            'role': str(self.role.pk),
            'justification': 'Need access',
            'requested_duration_minutes': '60',
        })
        req = AccessRequest.objects.first()
        self.assertIsNotNone(req)
        self.assertEqual(req.status, AccessRequest.Status.APPROVED)
        self.assertRedirects(response, reverse('requests:detail', kwargs={'pk': req.pk}))


class AccessRequestFormTests(TestCase):
    """Test duration clamping in the request form."""

    def setUp(self):
        self.role = PrivilegedRole.objects.create(
            name='Test-Role',
            provider='AWS',
            aws_permission_set_arn='ps-123',
            max_duration_minutes=240,
        )

    def _post_data(self, duration):
        return {
            'role': str(self.role.pk),
            'justification': 'Need access',
            'requested_duration_minutes': str(duration),
        }

    def test_duration_clamped_to_role_max(self):
        """Durations above the role max are clamped, not rejected."""
        form = AccessRequestForm(self._post_data(480))
        self.assertTrue(form.is_valid())
        self.assertEqual(form.cleaned_data['requested_duration_minutes'], 240)

    def test_duration_within_max_unchanged(self):
        """Durations within the max pass through unchanged."""
        form = AccessRequestForm(self._post_data(120))
        self.assertTrue(form.is_valid())
        self.assertEqual(form.cleaned_data['requested_duration_minutes'], 120)

    def test_create_view_clamps_and_warns(self):
        """The create view saves the clamped value and shows a warning."""
        user = User.objects.create_user(username='requester', password='testpass')
        self.client.force_login(user)
        response = self.client.post(reverse('requests:create'), self._post_data(480))
        req = AccessRequest.objects.first()
        self.assertIsNotNone(req)
        self.assertEqual(req.requested_duration_minutes, 240)
        messages = [str(m) for m in get_messages(response.wsgi_request)]
        self.assertTrue(any('was reduced' in m for m in messages))


class RoleApproverPermissionTests(TestCase):
    """Role approvers can approve regardless of their PAM-level role.

    Regression test: a user with PAM role REQUESTER who is listed in a role's
    approvers must see pending requests and be able to approve them (with MFA
    enrollment, since role approvers are MFA-required).
    """

    def setUp(self):
        self.requester = User.objects.create_user(
            username='requester', password='testpass',
        )
        self.role_approver = User.objects.create_user(
            username='role_approver', password='testpass',
            role=User.Role.REQUESTER,
        )
        self.role = PrivilegedRole.objects.create(
            name='Test-Role',
            provider='AWS',
            aws_permission_set_arn='ps-123',
        )
        self.role.approvers.add(self.role_approver)
        self.access_request = AccessRequest.objects.create(
            requester=self.requester,
            role=self.role,
            justification='Test',
        )

    def test_pending_list_visible_to_role_approver(self):
        """The pending-approvals page shows the request (no 403)."""
        self.client.force_login(self.role_approver)
        response = self.client.get(reverse('requests:pending_approvals'))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.context['requests']), 1)

    def test_poll_includes_pending_for_role_approver(self):
        """The live-updates poll counts their pending requests."""
        self.client.force_login(self.role_approver)
        response = self.client.get(reverse('requests:poll'))
        self.assertEqual(response.json()['pending_count'], 1)

    def test_detail_page_shows_actions_for_role_approver(self):
        """The approve/deny forms render for a PAM-level requester approver."""
        self.client.force_login(self.role_approver)
        response = self.client.get(reverse(
            'requests:detail', kwargs={'pk': self.access_request.pk}))
        self.assertContains(response, 'Approve')

    def test_mfa_required_for_role_approver(self):
        """Anyone who can approve is MFA-required."""
        self.assertTrue(self.role_approver.mfa_required)

    def test_unenrolled_role_approver_redirected_to_mfa_setup(self):
        """An unenrolled role approver is sent to MFA setup, not a 403."""
        self.client.force_login(self.role_approver)
        url = reverse('requests:approve', kwargs={'pk': self.access_request.pk})
        response = self.client.post(url, {'comment': 'ok'})
        self.assertRedirects(response, reverse('accounts:mfa_setup'))
        self.access_request.refresh_from_db()
        self.assertEqual(self.access_request.status, AccessRequest.Status.PENDING)

    @patch('tasks.provisioning.provision_access_sync')
    def test_enrolled_role_approver_can_approve(self, mock_provision):
        """An enrolled role approver completes the two-step approval."""
        self.role_approver.set_otp_secret(OTP_SECRET)
        self.role_approver.mfa_enrolled_at = timezone.now()
        self.role_approver.save()
        self.client.force_login(self.role_approver)
        url = reverse('requests:approve', kwargs={'pk': self.access_request.pk})
        response = self.client.post(url, {'comment': 'ok'})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'pam/mfa_challenge.html')
        ticket = self.client.session['mfa_ticket']
        response = self.client.post(reverse('accounts:mfa_challenge'), {
            'code': pyotp.TOTP(OTP_SECRET).now(),
            'comment': 'ok',
            'ticket': ticket,
            'target_id': str(self.access_request.pk),
        })
        self.access_request.refresh_from_db()
        self.assertEqual(self.access_request.status, AccessRequest.Status.APPROVED)
