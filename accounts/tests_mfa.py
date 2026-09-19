"""Tests for elevation-time MFA: enrollment, removal, and the challenge flow."""

from unittest.mock import patch

import pyotp
from django.contrib.auth import get_user_model
from django.contrib.messages import get_messages
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from access_requests.models import AccessRequest, Approval
from audit.models import AuditLog
from roles.models import PrivilegedRole

User = get_user_model()

# RFC 6238 test-vector secret, used to enroll users in MFA for tests
OTP_SECRET = 'JBSWY3DPEHPK3PXP'


def enroll(user):
    """Enroll a user in MFA with the test-vector secret."""
    user.set_otp_secret(OTP_SECRET)
    user.mfa_enrolled_at = timezone.now()
    user.save()


class MFASetupViewTests(TestCase):
    """Test MFA enrollment via the setup page."""

    def setUp(self):
        self.setup_url = reverse('accounts:mfa_setup')
        self.user = User.objects.create_user(
            username='testuser', password='testpass',
        )

    def test_mfa_setup_requires_login(self):
        """Setup requires authentication."""
        response = self.client.get(self.setup_url)
        self.assertEqual(response.status_code, 302)

    def test_mfa_setup_generates_secret_and_qr(self):
        """Setup page generates a secret, otpauth URI, and QR SVG."""
        self.client.force_login(self.user)
        response = self.client.get(self.setup_url)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'pam/mfa_setup.html')
        secret = response.context['secret']
        self.assertTrue(secret)
        self.assertIn('otpauth://', response.context['otpauth_uri'])
        self.assertIn('<svg', response.context['qr_svg'])
        # Secret persists across a refresh
        response2 = self.client.get(self.setup_url)
        self.assertEqual(response2.context['secret'], secret)

    def test_enroll_valid_code_saves_signed_secret(self):
        """A valid code against the pending secret enrolls the user."""
        self.client.force_login(self.user)
        self.client.get(self.setup_url)
        pending_secret = self.client.session['mfa_pending_secret']
        code = pyotp.TOTP(pending_secret).now()
        response = self.client.post(self.setup_url, {'code': code})
        self.assertRedirects(response, reverse('accounts:profile'))
        self.user.refresh_from_db()
        self.assertTrue(self.user.mfa_enrolled)
        self.assertEqual(self.user.get_otp_secret(), pending_secret)
        # Encrypted at rest: the stored field is signed (contains the ':')
        self.assertIn(':', self.user.otp_secret)
        self.assertIsNotNone(self.user.mfa_enrolled_at)
        self.assertTrue(AuditLog.objects.filter(
            actor=self.user, action='MFA_ENROLLED').exists())

    def test_enroll_invalid_code_does_not_save(self):
        """A wrong code does not enroll the user."""
        self.client.force_login(self.user)
        self.client.get(self.setup_url)
        response = self.client.post(self.setup_url, {'code': '000000'})
        self.assertRedirects(response, self.setup_url)
        self.user.refresh_from_db()
        self.assertFalse(self.user.mfa_enrolled)
        self.assertFalse(AuditLog.objects.filter(action='MFA_ENROLLED').exists())

    def test_re_enroll_replaces_secret(self):
        """Re-enrolling with a new secret replaces the old one."""
        enroll(self.user)
        old_secret = self.user.get_otp_secret()
        self.client.force_login(self.user)
        self.client.get(self.setup_url)
        pending_secret = self.client.session['mfa_pending_secret']
        self.assertNotEqual(pending_secret, old_secret)
        code = pyotp.TOTP(pending_secret).now()
        self.client.post(self.setup_url, {'code': code})
        self.user.refresh_from_db()
        self.assertEqual(self.user.get_otp_secret(), pending_secret)
        audit = AuditLog.objects.filter(actor=self.user, action='MFA_ENROLLED').last()
        self.assertTrue(audit.details.get('re_enroll'))


class MFARemoveViewTests(TestCase):
    """Test MFA removal."""

    def setUp(self):
        self.remove_url = reverse('accounts:mfa_remove')

    def test_remove_succeeds_for_requester(self):
        """A requester can remove MFA with a valid code."""
        user = User.objects.create_user(username='requester', password='testpass')
        enroll(user)
        self.client.force_login(user)
        code = pyotp.TOTP(OTP_SECRET).now()
        response = self.client.post(self.remove_url, {'code': code})
        self.assertRedirects(response, reverse('accounts:profile'))
        user.refresh_from_db()
        self.assertFalse(user.mfa_enrolled)
        self.assertEqual(user.get_otp_secret(), '')
        self.assertTrue(AuditLog.objects.filter(
            actor=user, action='MFA_REMOVED').exists())

    def test_remove_blocked_for_approver(self):
        """Approvers cannot remove MFA (their role requires it)."""
        user = User.objects.create_user(
            username='approver', password='testpass', role=User.Role.APPROVER)
        enroll(user)
        self.client.force_login(user)
        code = pyotp.TOTP(OTP_SECRET).now()
        response = self.client.post(self.remove_url, {'code': code})
        self.assertRedirects(response, reverse('accounts:profile'))
        messages = [str(m) for m in get_messages(response.wsgi_request)]
        self.assertTrue(any('cannot be removed' in m for m in messages))
        user.refresh_from_db()
        self.assertTrue(user.mfa_enrolled)
        self.assertFalse(AuditLog.objects.filter(action='MFA_REMOVED').exists())

    def test_remove_requires_valid_code(self):
        """A wrong code does not remove MFA."""
        user = User.objects.create_user(username='requester', password='testpass')
        enroll(user)
        self.client.force_login(user)
        self.client.post(self.remove_url, {'code': '000000'})
        user.refresh_from_db()
        self.assertTrue(user.mfa_enrolled)


class MFAApprovalFlowTests(TestCase):
    """Test the MFA gate on the approval flow."""

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
        self.role.approvers.add(self.approver)
        self.access_request = AccessRequest.objects.create(
            requester=self.requester,
            role=self.role,
            justification='Test',
        )
        self.approve_url = reverse(
            'requests:approve', kwargs={'pk': self.access_request.pk})

    def test_approve_unenrolled_approver_blocked(self):
        """An unenrolled approver is redirected to MFA setup, nothing executed."""
        self.client.force_login(self.approver)
        response = self.client.post(self.approve_url, {'comment': 'Approved'})
        self.assertRedirects(response, reverse('accounts:mfa_setup'))
        messages = [str(m) for m in get_messages(response.wsgi_request)]
        self.assertTrue(any('MFA enrollment is required' in m for m in messages))
        self.access_request.refresh_from_db()
        self.assertEqual(self.access_request.status, AccessRequest.Status.PENDING)
        self.assertEqual(Approval.objects.count(), 0)

    def test_approve_enrolled_renders_challenge(self):
        """An enrolled approver gets the challenge page; nothing executes yet."""
        enroll(self.approver)
        self.client.force_login(self.approver)
        response = self.client.post(self.approve_url, {'comment': 'Approved'})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'pam/mfa_challenge.html')
        # Regression: the form must POST to the challenge endpoint, not the
        # current URL (it renders as the response to the approve POST).
        self.assertContains(response, 'action="/accounts/mfa/challenge/"')
        self.assertIn('mfa_ticket', self.client.session)
        self.access_request.refresh_from_db()
        self.assertEqual(self.access_request.status, AccessRequest.Status.PENDING)
        self.assertEqual(Approval.objects.count(), 0)

    @patch('tasks.provisioning.provision_access_sync')
    def test_approve_challenge_success_executes(self, mock_provision):
        """A valid code executes the approval."""
        enroll(self.approver)
        self.client.force_login(self.approver)
        self.client.post(self.approve_url, {'comment': 'Approved'})
        ticket = self.client.session['mfa_ticket']
        code = pyotp.TOTP(OTP_SECRET).now()
        response = self.client.post(reverse('accounts:mfa_challenge'), {
            'code': code,
            'comment': 'Approved',
            'ticket': ticket,
            'target_id': str(self.access_request.pk),
        })
        self.assertRedirects(
            response,
            reverse('requests:detail', kwargs={'pk': self.access_request.pk}))
        self.access_request.refresh_from_db()
        self.assertEqual(self.access_request.status, AccessRequest.Status.APPROVED)
        self.assertEqual(Approval.objects.count(), 1)
        # Ticket is single-use
        self.assertNotIn('mfa_ticket', self.client.session)

    def test_approve_challenge_wrong_code_no_execution(self):
        """A wrong code does not execute the approval and is audited."""
        enroll(self.approver)
        self.client.force_login(self.approver)
        self.client.post(self.approve_url, {'comment': 'Approved'})
        ticket = self.client.session['mfa_ticket']
        response = self.client.post(reverse('accounts:mfa_challenge'), {
            'code': '000000',
            'comment': 'Approved',
            'ticket': ticket,
            'target_id': str(self.access_request.pk),
        })
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'pam/mfa_challenge.html')
        self.access_request.refresh_from_db()
        self.assertEqual(self.access_request.status, AccessRequest.Status.PENDING)
        self.assertEqual(Approval.objects.count(), 0)
        self.assertTrue(AuditLog.objects.filter(
            action='MFA_CHALLENGE_FAILED',
            details__action='approve_request').exists())

    def test_lockout_after_five_failures(self):
        """Five failed codes lock the session, even for a correct code after."""
        enroll(self.approver)
        self.client.force_login(self.approver)
        self.client.post(self.approve_url, {'comment': 'Approved'})
        ticket = self.client.session['mfa_ticket']
        challenge_url = reverse('accounts:mfa_challenge')
        for _ in range(5):
            self.client.post(challenge_url, {
                'code': '000000',
                'comment': 'Approved',
                'ticket': ticket,
                'target_id': str(self.access_request.pk),
            })
        # Correct code is now rejected while locked
        code = pyotp.TOTP(OTP_SECRET).now()
        response = self.client.post(challenge_url, {
            'code': code,
            'comment': 'Approved',
            'ticket': ticket,
            'target_id': str(self.access_request.pk),
        })
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Too many failed attempts')
        self.access_request.refresh_from_db()
        self.assertEqual(self.access_request.status, AccessRequest.Status.PENDING)
        self.assertEqual(Approval.objects.count(), 0)

    def test_ticket_tampering_rejected(self):
        """A tampered ticket is rejected without executing anything."""
        enroll(self.approver)
        self.client.force_login(self.approver)
        self.client.post(self.approve_url, {'comment': 'Approved'})
        response = self.client.post(reverse('accounts:mfa_challenge'), {
            'code': pyotp.TOTP(OTP_SECRET).now(),
            'comment': 'Approved',
            'ticket': 'garbage-ticket',
            'target_id': str(self.access_request.pk),
        })
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'stale')
        self.access_request.refresh_from_db()
        self.assertEqual(self.access_request.status, AccessRequest.Status.PENDING)
        self.assertEqual(Approval.objects.count(), 0)

    def test_ticket_user_mismatch_rejected(self):
        """A ticket issued for user A is rejected when posted by user B."""
        enroll(self.approver)
        self.client.force_login(self.approver)
        self.client.post(self.approve_url, {'comment': 'Approved'})
        ticket = self.client.session['mfa_ticket']
        # Another user logs in and replays A's ticket (planted in their
        # session, simulating a copied/leaked ticket). force_login flushes
        # the session on user change, so plant the ticket manually after.
        other = User.objects.create_user(
            username='other', password='testpass', role=User.Role.APPROVER)
        self.client.force_login(other)
        session = self.client.session
        session['mfa_ticket'] = ticket
        session.save()
        response = self.client.post(reverse('accounts:mfa_challenge'), {
            'code': pyotp.TOTP(OTP_SECRET).now(),
            'comment': 'Approved',
            'ticket': ticket,
            'target_id': str(self.access_request.pk),
        })
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'does not belong to the current user')
        self.access_request.refresh_from_db()
        self.assertEqual(self.access_request.status, AccessRequest.Status.PENDING)
        self.assertEqual(Approval.objects.count(), 0)

    def test_deny_is_not_challenged(self):
        """Deny is never MFA-challenged (policy)."""
        enroll(self.approver)
        self.client.force_login(self.approver)
        url = reverse('requests:deny', kwargs={'pk': self.access_request.pk})
        response = self.client.post(url, {'comment': 'Denied'})
        self.assertNotEqual(response.status_code, 200)
        self.access_request.refresh_from_db()
        self.assertEqual(self.access_request.status, AccessRequest.Status.DENIED)
        self.assertEqual(Approval.objects.count(), 1)


class MFACodeNormalizationTests(TestCase):
    """Codes with formatting (spaces, dashes) are accepted (regression)."""

    def setUp(self):
        self.user = User.objects.create_user(username='user', password='testpass')
        enroll(self.user)

    def test_verify_totp_accepts_spaced_code(self):
        """'123 456' style codes from authenticator apps verify fine."""
        from accounts.mfa import verify_totp
        code = pyotp.TOTP(OTP_SECRET).now()
        spaced = f'{code[:3]} {code[3:]}'
        self.assertTrue(verify_totp(self.user, spaced))

    def test_verify_totp_accepts_dashed_code(self):
        """'123-456' style codes verify fine."""
        from accounts.mfa import verify_totp
        code = pyotp.TOTP(OTP_SECRET).now()
        self.assertTrue(verify_totp(self.user, f'{code[:3]}-{code[3:]}'))

    def test_verify_totp_rejects_wrong_code(self):
        """Normalization does not weaken verification."""
        from accounts.mfa import verify_totp
        self.assertFalse(verify_totp(self.user, '000 000'))

    def test_enroll_accepts_spaced_code(self):
        """Enrollment via the setup page accepts a spaced code."""
        self.client.force_login(self.user)
        self.client.get(reverse('accounts:mfa_setup'))
        pending = self.client.session['mfa_pending_secret']
        code = pyotp.TOTP(pending).now()
        response = self.client.post(
            reverse('accounts:mfa_setup'),
            {'code': f'{code[:3]} {code[3:]}'})
        self.assertRedirects(response, reverse('accounts:profile'))
        self.user.refresh_from_db()
        self.assertTrue(self.user.mfa_enrolled)


class MFARequiredPolicyTests(TestCase):
    """Test the mfa_required policy."""

    def test_plain_requester_not_required(self):
        """A user who can approve nothing is not MFA-required."""
        user = User.objects.create_user(username='plain', password='testpass')
        self.assertFalse(user.mfa_required)

    def test_role_approver_is_required(self):
        """Being listed as a role approver makes a user MFA-required."""
        user = User.objects.create_user(
            username='role_approver', password='testpass',
            role=User.Role.REQUESTER)
        role = PrivilegedRole.objects.create(
            name='Policy-Role', provider='AWS', aws_permission_set_arn='ps-1')
        role.approvers.add(user)
        user.refresh_from_db()
        self.assertTrue(user.mfa_required)


class MFASubmitFlowTests(TestCase):
    """Test the MFA gate on request submission."""

    def setUp(self):
        self.create_url = reverse('requests:create')
        self.role = PrivilegedRole.objects.create(
            name='Test-Role',
            provider='AWS',
            aws_permission_set_arn='ps-123',
        )
        self.post_data = {
            'role': str(self.role.pk),
            'justification': 'Need access',
            'requested_duration_minutes': '120',
        }

    def test_requester_unenrolled_submits_without_challenge(self):
        """An unenrolled requester submits directly (regression)."""
        user = User.objects.create_user(username='requester', password='testpass')
        self.client.force_login(user)
        response = self.client.post(self.create_url, self.post_data)
        self.assertEqual(AccessRequest.objects.count(), 1)
        request_obj = AccessRequest.objects.first()
        self.assertRedirects(
            response, reverse('requests:detail', kwargs={'pk': request_obj.pk}))

    @patch('notifications.services.send_notification')
    def test_requester_enrolled_submit_challenged_then_created(self, mock_notify):
        """An enrolled requester must pass the challenge before creation."""
        user = User.objects.create_user(username='requester', password='testpass')
        enroll(user)
        self.client.force_login(user)
        response = self.client.post(self.create_url, self.post_data)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'pam/mfa_challenge.html')
        self.assertEqual(AccessRequest.objects.count(), 0)
        ticket = self.client.session['mfa_ticket']
        code = pyotp.TOTP(OTP_SECRET).now()
        challenge_data = dict(self.post_data)
        challenge_data.update({
            'code': code,
            'ticket': ticket,
            'target_id': '',
        })
        response = self.client.post(reverse('accounts:mfa_challenge'), challenge_data)
        self.assertEqual(AccessRequest.objects.count(), 1)
        request_obj = AccessRequest.objects.first()
        self.assertEqual(request_obj.requester, user)
        self.assertRedirects(
            response, reverse('requests:detail', kwargs={'pk': request_obj.pk}))
        self.assertTrue(AuditLog.objects.filter(
            action='REQUEST_CREATED').exists())
