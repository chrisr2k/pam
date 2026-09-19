"""Tests for break-glass emergency access."""

from unittest.mock import patch

import pyotp
from django.contrib.auth import get_user_model
from django.contrib.messages import get_messages
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from audit.models import AuditLog
from roles.models import PrivilegedRole
from .models import AccessRequest, Approval

User = get_user_model()

OTP_SECRET = 'JBSWY3DPEHPK3PXP'


def enroll(user):
    """Enroll a user in MFA with the test-vector secret."""
    user.set_otp_secret(OTP_SECRET)
    user.mfa_enrolled_at = timezone.now()
    user.save()


class BreakGlassViewTests(TestCase):
    """Test the break-glass flow (admins only, MFA mandatory)."""

    def setUp(self):
        self.bg_url = reverse('requests:break_glass')
        self.admin = User.objects.create_user(
            username='admin', password='adminpass',
            role=User.Role.ADMIN, email='admin@example.com',
        )
        self.staff = User.objects.create_user(
            username='staff', password='staffpass',
            is_staff=True, email='staff@example.com',
        )
        self.requester = User.objects.create_user(
            username='requester', password='testpass',
        )
        self.approver = User.objects.create_user(
            username='approver', password='testpass',
            role=User.Role.APPROVER,
        )
        self.role = PrivilegedRole.objects.create(
            name='AWS-Admin',
            provider='AWS',
            aws_permission_set_arn='ps-admin',
            is_break_glass=True,
            max_duration_minutes=480,
        )
        self.normal_role = PrivilegedRole.objects.create(
            name='AWS-ReadOnly',
            provider='AWS',
            aws_permission_set_arn='ps-readonly',
        )

    def _drive_challenge(self, code, extra=None):
        """POST the MFA challenge with the current session ticket."""
        data = {
            'code': code,
            'ticket': self.client.session.get('mfa_ticket', ''),
            'target_id': str(self.role.pk),
        }
        if extra:
            data.update(extra)
        return self.client.post(reverse('accounts:mfa_challenge'), data)

    def test_break_glass_requires_admin(self):
        """Requesters and approvers get 403; admins/staff get the page."""
        for user, expected in (
            (self.requester, 403),
            (self.approver, 403),
            (self.admin, 200),
            (self.staff, 200),
        ):
            self.client.force_login(user)
            response = self.client.get(self.bg_url)
            self.assertEqual(response.status_code, expected, f'user={user.username}')

    def test_form_lists_only_flagged_roles(self):
        """Only is_break_glass roles appear in the form."""
        self.client.force_login(self.admin)
        response = self.client.get(self.bg_url)
        role_pks = [r.pk for r in response.context['roles']]
        self.assertIn(self.role.pk, role_pks)
        self.assertNotIn(self.normal_role.pk, role_pks)

    def test_unenrolled_admin_blocked_with_enroll_message(self):
        """An unenrolled admin is redirected to MFA setup; nothing created."""
        self.client.force_login(self.admin)
        response = self.client.post(self.bg_url, {
            'role': str(self.role.pk),
            'justification': 'Incident',
            'duration_minutes': '30',
        })
        self.assertRedirects(response, reverse('accounts:mfa_setup'))
        messages = [str(m) for m in get_messages(response.wsgi_request)]
        self.assertTrue(any('must set up MFA' in m for m in messages))
        self.assertEqual(AccessRequest.objects.count(), 0)

    def test_enrolled_admin_gets_challenge(self):
        """An enrolled admin POST gets the challenge page; nothing created yet."""
        enroll(self.admin)
        self.client.force_login(self.admin)
        response = self.client.post(self.bg_url, {
            'role': str(self.role.pk),
            'justification': 'Incident',
            'duration_minutes': '30',
        })
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'pam/mfa_challenge.html')
        # Regression: the form must POST to the challenge endpoint, not back
        # to the break-glass URL it rendered from.
        self.assertContains(response, 'action="/accounts/mfa/challenge/"')
        self.assertEqual(AccessRequest.objects.count(), 0)
        self.assertIn('mfa_ticket', self.client.session)

    @patch('tasks.provisioning.provision_access_sync')
    @patch('access_requests.services.send_notification')
    def test_success_creates_approved_break_glass_request(self, mock_notify, mock_provision):
        """A valid challenge creates an APPROVED break-glass request."""
        enroll(self.admin)
        self.client.force_login(self.admin)
        self.client.post(self.bg_url, {
            'role': str(self.role.pk),
            'justification': 'Production outage',
            'duration_minutes': '45',
        })
        response = self._drive_challenge(
            pyotp.TOTP(OTP_SECRET).now(),
            extra={'role': str(self.role.pk),
                   'justification': 'Production outage',
                   'duration_minutes': '45'},
        )
        self.assertEqual(AccessRequest.objects.count(), 1)
        req = AccessRequest.objects.first()
        self.assertRedirects(response, reverse('requests:detail', kwargs={'pk': req.pk}))
        self.assertEqual(req.status, AccessRequest.Status.APPROVED)
        self.assertTrue(req.is_break_glass)
        self.assertEqual(req.approved_by, self.admin)
        self.assertEqual(req.requested_duration_minutes, 45)
        self.assertEqual(Approval.objects.count(), 0)

    @patch('tasks.provisioning.provision_access_sync')
    def test_duration_clamped_to_break_glass_max(self, mock_provision):
        """Durations are clamped to PAM_BREAK_GLASS_DURATION_MINUTES (60)."""
        enroll(self.admin)
        self.client.force_login(self.admin)
        self.client.post(self.bg_url, {
            'role': str(self.role.pk),
            'justification': 'Incident',
            'duration_minutes': '9999',
        })
        self._drive_challenge(
            pyotp.TOTP(OTP_SECRET).now(),
            extra={'role': str(self.role.pk),
                   'justification': 'Incident',
                   'duration_minutes': '9999'},
        )
        req = AccessRequest.objects.first()
        self.assertEqual(req.requested_duration_minutes, 60)

    @patch('tasks.provisioning.provision_access_sync')
    def test_duration_clamped_to_role_max(self, mock_provision):
        """Durations are clamped to the role's max_duration_minutes."""
        self.role.max_duration_minutes = 30
        self.role.save()
        enroll(self.admin)
        self.client.force_login(self.admin)
        self.client.post(self.bg_url, {
            'role': str(self.role.pk),
            'justification': 'Incident',
            'duration_minutes': '45',
        })
        self._drive_challenge(
            pyotp.TOTP(OTP_SECRET).now(),
            extra={'role': str(self.role.pk),
                   'justification': 'Incident',
                   'duration_minutes': '45'},
        )
        req = AccessRequest.objects.first()
        self.assertEqual(req.requested_duration_minutes, 30)

    def test_non_flagged_role_rejected(self):
        """POSTing a non-flagged role is rejected with 404."""
        enroll(self.admin)
        self.client.force_login(self.admin)
        response = self.client.post(self.bg_url, {
            'role': str(self.normal_role.pk),
            'justification': 'Incident',
            'duration_minutes': '30',
        })
        self.assertEqual(response.status_code, 404)
        self.assertEqual(AccessRequest.objects.count(), 0)

    def test_wrong_code_creates_nothing(self):
        """A wrong TOTP code creates nothing and is audited."""
        enroll(self.admin)
        self.client.force_login(self.admin)
        self.client.post(self.bg_url, {
            'role': str(self.role.pk),
            'justification': 'Incident',
            'duration_minutes': '30',
        })
        response = self._drive_challenge(
            '000000',
            extra={'role': str(self.role.pk),
                   'justification': 'Incident',
                   'duration_minutes': '30'},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(AccessRequest.objects.count(), 0)
        self.assertTrue(AuditLog.objects.filter(
            action='MFA_CHALLENGE_FAILED',
            details__action='break_glass').exists())

    @patch('tasks.provisioning.provision_access_sync')
    def test_audit_event_written(self, mock_provision):
        """A BREAK_GLASS_TRIGGERED audit row is written with role details."""
        enroll(self.admin)
        self.client.force_login(self.admin)
        self.client.post(self.bg_url, {
            'role': str(self.role.pk),
            'justification': 'Production outage',
            'duration_minutes': '30',
        })
        self._drive_challenge(
            pyotp.TOTP(OTP_SECRET).now(),
            extra={'role': str(self.role.pk),
                   'justification': 'Production outage',
                   'duration_minutes': '30'},
        )
        audit = AuditLog.objects.filter(action='BREAK_GLASS_TRIGGERED').first()
        self.assertIsNotNone(audit)
        self.assertEqual(audit.actor, self.admin)
        self.assertEqual(audit.details['role'], 'AWS-Admin')
        self.assertEqual(audit.details['duration_minutes'], 30)

    @patch('tasks.provisioning.provision_access_sync')
    @patch('access_requests.services.send_notification')
    def test_notifies_all_admins(self, mock_notify, mock_provision):
        """All admin/staff emails receive the break-glass alert."""
        enroll(self.admin)
        self.client.force_login(self.admin)
        self.client.post(self.bg_url, {
            'role': str(self.role.pk),
            'justification': 'Production outage',
            'duration_minutes': '30',
        })
        self._drive_challenge(
            pyotp.TOTP(OTP_SECRET).now(),
            extra={'role': str(self.role.pk),
                   'justification': 'Production outage',
                   'duration_minutes': '30'},
        )
        mock_notify.assert_called_once()
        args, kwargs = mock_notify.call_args
        self.assertEqual(args[1], 'break_glass_triggered')
        recipients = kwargs['recipients']
        self.assertIn('admin@example.com', recipients)
        self.assertIn('staff@example.com', recipients)
        self.assertNotIn('', recipients)

    def test_detail_page_shows_badge(self):
        """The request detail page shows the BREAK GLASS badge."""
        req = AccessRequest.objects.create(
            requester=self.requester,
            role=self.role,
            justification='Test',
            status=AccessRequest.Status.APPROVED,
            is_break_glass=True,
        )
        self.client.force_login(self.requester)
        response = self.client.get(reverse('requests:detail', kwargs={'pk': req.pk}))
        self.assertContains(response, 'BREAK GLASS')
