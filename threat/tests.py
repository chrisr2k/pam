"""Tests for threat analytics: rules, scan task, views."""

from datetime import timedelta
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from audit.models import AuditLog
from .models import ThreatAlert, ThreatConfig
from .rules import (
    CheckoutSpikeRule,
    ImpossibleTravelRule,
    MfaStormRule,
    OffHoursElevationRule,
    RevealSpikeRule,
)

User = get_user_model()


def _log(action, actor=None, ip=None, ts=None, target_id='', details=None, **extra):
    # timestamp is auto_now_add, which ignores explicit values on INSERT;
    # force controlled timestamps via update() (auto_now_add is insert-only)
    # and sync the in-memory attribute so callers see the forced value.
    entry = AuditLog.objects.create(
        actor=actor, action=action, ip_address=ip,
        target_id=target_id or '', details=details or {}, **extra)
    if ts is not None:
        AuditLog.objects.filter(pk=entry.pk).update(timestamp=ts)
        entry.timestamp = ts
    return entry


class RuleTests(TestCase):
    """Unit tests for the detection rules."""

    def setUp(self):
        self.config = ThreatConfig.get_config()
        self.now = timezone.now()
        self.user = User.objects.create_user(username='u1', password='x')

    def _since(self, minutes):
        return self.now - timedelta(minutes=minutes)

    # ── Impossible travel ──

    def test_impossible_travel_no_alert_below_ip_threshold(self):
        _log('LOGIN', actor=self.user, ip='10.0.0.1', ts=self.now - timedelta(minutes=5))
        findings = ImpossibleTravelRule().evaluate(
            self.config, self.now, self._since(30))
        self.assertEqual(findings, [])

    def test_impossible_travel_alerts_different_subnets(self):
        ids = [
            _log('LOGIN', actor=self.user, ip='10.0.0.1', ts=self.now - timedelta(minutes=5)).pk,
            _log('LOGIN', actor=self.user, ip='172.16.9.9', ts=self.now - timedelta(minutes=2)).pk,
        ]
        findings = ImpossibleTravelRule().evaluate(
            self.config, self.now, self._since(30))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].dedup_key, f'actor:{self.user.pk}')
        self.assertIn('networks', findings[0].details)
        self.assertEqual(findings[0].related_audit_ids, ids)

    def test_impossible_travel_same_subnet_no_alert(self):
        _log('LOGIN', actor=self.user, ip='10.0.0.1', ts=self.now)
        _log('LOGIN', actor=self.user, ip='10.0.0.99', ts=self.now)
        findings = ImpossibleTravelRule().evaluate(
            self.config, self.now, self._since(30))
        self.assertEqual(findings, [])

    def test_impossible_travel_ignores_null_ip_and_anonymous(self):
        _log('LOGIN', actor=self.user, ip=None, ts=self.now)
        _log('LOGIN', actor=None, ip='192.168.0.1', ts=self.now)
        findings = ImpossibleTravelRule().evaluate(
            self.config, self.now, self._since(30))
        self.assertEqual(findings, [])

    def test_impossible_travel_respects_window(self):
        _log('LOGIN', actor=self.user, ip='10.0.0.1', ts=self.now - timedelta(minutes=40))
        _log('LOGIN', actor=self.user, ip='172.16.0.1', ts=self.now - timedelta(minutes=35))
        findings = ImpossibleTravelRule().evaluate(
            self.config, self.now, self._since(30))
        self.assertEqual(findings, [])

    # ── Off-hours elevation ──

    def _off_hours_log(self, hour, action='BREAK_GLASS_TRIGGERED', actor=None):
        # Land on a guaranteed weekday so the weekend flag never interferes
        # with weekday-window assertions.
        ts = timezone.now()
        while ts.weekday() >= 5:
            ts -= timedelta(days=1)
        ts = ts.replace(hour=hour, minute=0, second=0, microsecond=0)
        return _log(action, actor=actor or self.user, ts=ts)

    def _evaluate_around(self, ts):
        """Evaluate with a scan window centered on the fabricated timestamp."""
        return OffHoursElevationRule().evaluate(
            self.config, ts + timedelta(minutes=30), ts - timedelta(minutes=30))

    def test_off_hours_evening_elevation(self):
        """19:00 UTC with overnight range 18:00-07:00 → finding."""
        ts = self._off_hours_log(19).timestamp
        findings = self._evaluate_around(ts)
        self.assertEqual(len(findings), 1)
        self.assertIn('off-hours', findings[0].summary)

    def test_off_hours_early_morning(self):
        ts = self._off_hours_log(3).timestamp
        findings = self._evaluate_around(ts)
        self.assertEqual(len(findings), 1)

    def test_off_hours_inside_hours_no_alert(self):
        ts = self._off_hours_log(12).timestamp
        findings = self._evaluate_around(ts)
        self.assertEqual(findings, [])

    def test_off_hours_weekend_elevation(self):
        """A past Saturday midday with the weekend flag on → finding."""
        ts = timezone.now()
        while ts.weekday() != 5:  # step back to the previous Saturday
            ts -= timedelta(days=1)
        ts = ts.replace(hour=12, minute=0, second=0, microsecond=0)
        _log('REQUEST_APPROVED', actor=self.user, ts=ts)
        self.config.off_hours_weekend = True
        self.config.save()
        findings = OffHoursElevationRule().evaluate(
            self.config, timezone.now(), timezone.now() - timedelta(days=7))
        self.assertEqual(len(findings), 1)

    def test_off_hours_weekend_disabled_no_alert(self):
        ts = timezone.now()
        while ts.weekday() != 5:  # step back to the previous Saturday
            ts -= timedelta(days=1)
        ts = ts.replace(hour=12, minute=0, second=0, microsecond=0)
        _log('REQUEST_APPROVED', actor=self.user, ts=ts)
        self.config.off_hours_weekend = False
        self.config.save()
        findings = OffHoursElevationRule().evaluate(
            self.config, timezone.now(), timezone.now() - timedelta(days=7))
        self.assertEqual(findings, [])

    def test_off_hours_start_equals_end_no_weekday_window(self):
        """start == end disables the weekday window (documented)."""
        self.config.off_hours_start = '09:00'
        self.config.off_hours_end = '09:00'
        self.config.off_hours_weekend = False
        self.config.save()
        ts = self._off_hours_log(3).timestamp
        findings = self._evaluate_around(ts)
        self.assertEqual(findings, [])

    # ── MFA storm ──

    def test_mfa_storm_below_threshold(self):
        for _ in range(4):
            _log('MFA_CHALLENGE_FAILED', actor=self.user, ts=self.now)
        findings = MfaStormRule().evaluate(self.config, self.now, self._since(10))
        self.assertEqual(findings, [])

    def test_mfa_storm_above_threshold(self):
        for _ in range(5):
            _log('MFA_CHALLENGE_FAILED', actor=self.user, ts=self.now)
        findings = MfaStormRule().evaluate(self.config, self.now, self._since(10))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].dedup_key, f'actor:{self.user.pk}')
        self.assertIn('5 times', findings[0].summary)

    # ── Checkout spike ──

    def test_checkout_spike_per_actor(self):
        for _ in range(10):
            _log('REQUEST_CREATED', actor=self.user, ts=self.now)
        other = User.objects.create_user(username='u2', password='x')
        for _ in range(2):
            _log('REQUEST_CREATED', actor=other, ts=self.now)
        findings = CheckoutSpikeRule().evaluate(
            self.config, self.now, self._since(60))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].dedup_key, f'actor:{self.user.pk}')

    # ── Reveal spike ──

    def test_reveal_spike_groups_by_entry(self):
        for _ in range(5):
            _log('VAULT_SECRET_REVEALED', actor=self.user, target_id='7',
                 details={'entry': 'Prod-DB'}, ts=self.now)
        for _ in range(2):
            _log('VAULT_SECRET_REVEALED', actor=self.user, target_id='8',
                 details={'entry': 'Other'}, ts=self.now)
        findings = RevealSpikeRule().evaluate(self.config, self.now, self._since(10))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].dedup_key, 'entry:7')
        self.assertEqual(findings[0].details['entry'], 'Prod-DB')

    def test_reveal_spike_ignores_empty_target_id(self):
        for _ in range(5):
            _log('VAULT_SECRET_REVEALED', actor=self.user, target_id='', ts=self.now)
        findings = RevealSpikeRule().evaluate(self.config, self.now, self._since(10))
        self.assertEqual(findings, [])


class ScanTaskTests(TestCase):
    """Test the scan_threats task end-to-end."""

    def setUp(self):
        self.config = ThreatConfig.get_config()
        self.user = User.objects.create_user(username='u1', password='x')
        self.now = timezone.now()

    def _storm(self, count=5):
        for _ in range(count):
            _log('MFA_CHALLENGE_FAILED', actor=self.user, ts=self.now)

    @patch('notifications.services.send_alert_notification')
    def test_scan_creates_alert_and_audit_row(self, mock_notify):
        self._storm()
        from .tasks import scan_threats
        scan_threats.run()
        alert = ThreatAlert.objects.get(rule='mfa_storm')
        self.assertEqual(alert.severity, ThreatAlert.Severity.CRITICAL)
        self.assertTrue(AuditLog.objects.filter(
            action='ALERT_RAISED', target_type='ThreatAlert',
            target_id=str(alert.pk), actor=None).exists())
        mock_notify.assert_called_once()

    @patch('notifications.services.send_alert_notification')
    def test_scan_respects_cooldown(self, mock_notify):
        self._storm()
        from .tasks import scan_threats
        scan_threats.run()
        self.assertEqual(ThreatAlert.objects.count(), 1)
        scan_threats.run()  # within cooldown → suppressed entirely
        self.assertEqual(ThreatAlert.objects.count(), 1)
        self.assertEqual(mock_notify.call_count, 1)
        self.assertEqual(AuditLog.objects.filter(action='ALERT_RAISED').count(), 1)

    @patch('notifications.services.send_alert_notification')
    def test_scan_after_cooldown_creates_new_alert(self, mock_notify):
        self._storm()
        from .tasks import scan_threats
        scan_threats.run()
        ThreatAlert.objects.update(
            created_at=timezone.now() - timedelta(minutes=60))
        scan_threats.run()
        self.assertEqual(ThreatAlert.objects.count(), 2)

    @patch('notifications.services.send_alert_notification')
    def test_scan_respects_disabled_rule(self, mock_notify):
        self.config.mfa_storm_enabled = False
        self.config.save()
        self._storm()
        from .tasks import scan_threats
        scan_threats.run()
        self.assertEqual(ThreatAlert.objects.count(), 0)

    @patch('notifications.services.send_alert_notification')
    def test_scan_updates_last_run_at(self, mock_notify):
        from .tasks import scan_threats
        scan_threats.run()
        self.config.refresh_from_db()
        self.assertIsNotNone(self.config.last_run_at)

    @patch('notifications.services.send_alert_notification')
    def test_scan_master_switch_disabled(self, mock_notify):
        self.config.scan_enabled = False
        self.config.save()
        self._storm()
        from .tasks import scan_threats
        scan_threats.run()
        self.assertEqual(ThreatAlert.objects.count(), 0)
        self.config.refresh_from_db()
        self.assertIsNotNone(self.config.last_run_at)

    def test_send_alert_notification_email_recipients(self):
        """Email recipients are all admins/staff; the email fires when set."""
        from notifications.models import NotificationConfig
        from notifications.services import send_alert_notification
        User.objects.create_user(
            username='admin1', password='x', role='ADMIN', email='a@example.com')
        User.objects.create_user(
            username='staff1', password='x', is_staff=True, email='s@example.com')
        config = NotificationConfig.get_config()
        config.email_enabled = True
        config.smtp_host = 'smtp.example.com'
        config.save()
        self._storm()
        from .tasks import scan_threats
        with patch('notifications.services.send_alert_notification'):
            scan_threats.run()
        alert = ThreatAlert.objects.first()
        with patch('notifications.services._send_email') as mock_email, \
             patch('notifications.services._post_webhook') as mock_webhook:
            send_alert_notification(alert)
        self.assertEqual(mock_email.call_count, 1)
        recipients = mock_email.call_args[0][3]
        self.assertIn('a@example.com', recipients)
        self.assertIn('s@example.com', recipients)


class ThreatViewTests(TestCase):
    """Test the alerts/settings/acknowledge views."""

    def setUp(self):
        self.staff = User.objects.create_user(
            username='staff', password='x', is_staff=True)
        self.requester = User.objects.create_user(username='req', password='x')
        ThreatAlert.objects.create(
            rule='mfa_storm', severity='CRITICAL', summary='Test alert',
            dedup_key='actor:1')

    def test_alerts_view_requires_staff_or_admin(self):
        self.client.force_login(self.requester)
        self.assertEqual(self.client.get(reverse('threat:list')).status_code, 403)
        self.client.force_login(self.staff)
        response = self.client.get(reverse('threat:list'))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Test alert')

    def test_alerts_view_rule_filter(self):
        self.client.force_login(self.staff)
        response = self.client.get(reverse('threat:list'), {'rule': 'reveal_spike'})
        self.assertEqual(len(response.context['alerts']), 0)
        response = self.client.get(reverse('threat:list'), {'rule': 'nonsense'})
        self.assertEqual(len(response.context['alerts']), 1)  # invalid ignored

    def test_settings_view_permissions_and_save(self):
        self.client.force_login(self.requester)
        self.assertEqual(self.client.get(reverse('threat:settings')).status_code, 403)
        self.client.force_login(self.staff)
        response = self.client.post(reverse('threat:settings'), {
            'scan_enabled': 'on',
            'cooldown_minutes': '15',
            'mfa_storm_threshold': '3',
            'off_hours_start': 'bad-time',
            'off_hours_end': '07:00',
            'off_hours_weekend': 'on',
        })
        self.assertRedirects(response, reverse('threat:settings'))
        config = ThreatConfig.get_config()
        self.assertEqual(config.cooldown_minutes, 15)
        self.assertEqual(config.mfa_storm_threshold, 3)
        self.assertEqual(config.off_hours_start, '18:00')  # invalid kept

    def test_acknowledge_view(self):
        alert = ThreatAlert.objects.first()
        self.client.force_login(self.requester)
        response = self.client.post(
            reverse('threat:acknowledge', kwargs={'pk': alert.pk}))
        self.assertEqual(response.status_code, 403)
        self.client.force_login(self.staff)
        response = self.client.post(
            reverse('threat:acknowledge', kwargs={'pk': alert.pk}))
        self.assertRedirects(response, reverse('threat:list'))
        alert.refresh_from_db()
        self.assertEqual(alert.acknowledged_by, self.staff)
        self.assertIsNotNone(alert.acknowledged_at)

    def test_alert_raised_action_display(self):
        self.assertEqual(
            AuditLog(action='ALERT_RAISED').get_action_display(), 'Threat Alert Raised')
