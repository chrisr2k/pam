"""Tests for SIEM export: config model, forwarder task, and login/logout emissions."""

from unittest.mock import MagicMock, patch

from django.conf import settings
from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

from .models import AuditLog, SIEMConfig
from .tasks import (
    _build_http_payload,
    _post,
    _serialize_event,
    forward_audit_events,
)

User = get_user_model()


class SIEMConfigModelTests(TestCase):
    """Test the SIEMConfig singleton model."""

    def setUp(self):
        SIEMConfig.objects.all().delete()

    def test_api_token_encrypted_at_rest(self):
        """The stored token is signed; get_api_token returns plaintext."""
        config = SIEMConfig.get_config()
        config.set_api_token('siem-secret-token')
        config.save()
        config.refresh_from_db()
        self.assertIn(':', config.api_token)
        self.assertEqual(config.get_api_token(), 'siem-secret-token')

    def test_singleton(self):
        """Only one SIEMConfig row can exist."""
        SIEMConfig.get_config()
        SIEMConfig.get_config()
        self.assertEqual(SIEMConfig.objects.count(), 1)


class SIEMSettingsViewTests(TestCase):
    """Test the SIEM settings page."""

    def setUp(self):
        SIEMConfig.objects.all().delete()
        self.settings_url = reverse('audit:siem_settings')
        self.requester = User.objects.create_user(username='requester', password='testpass')
        self.staff = User.objects.create_user(
            username='staff', password='testpass', is_staff=True)

    def test_settings_requires_admin_or_staff(self):
        """Requesters get 403; staff get the page."""
        self.client.force_login(self.requester)
        self.assertEqual(self.client.get(self.settings_url).status_code, 403)
        self.client.force_login(self.staff)
        self.assertEqual(self.client.get(self.settings_url).status_code, 200)

    def test_blank_token_keeps_old_value(self):
        """Submitting a blank token preserves the existing one."""
        config = SIEMConfig.get_config()
        config.set_api_token('existing-token')
        config.save()
        self.client.force_login(self.staff)
        self.client.post(self.settings_url, {
            'enabled': 'on',
            'webhook_url': 'https://siem.example/collect',
            'payload_mode': 'splunk_hec',
            'api_token': '',
            'token_header': 'Authorization',
            'token_prefix': 'Splunk ',
            'action_filter': '',
        })
        config.refresh_from_db()
        self.assertEqual(config.get_api_token(), 'existing-token')

    def test_new_token_replaces_old(self):
        """A non-blank token replaces the stored one."""
        config = SIEMConfig.get_config()
        config.set_api_token('existing-token')
        config.save()
        self.client.force_login(self.staff)
        self.client.post(self.settings_url, {
            'enabled': 'on',
            'webhook_url': 'https://siem.example/collect',
            'payload_mode': 'splunk_hec',
            'api_token': 'new-token',
            'token_header': 'Authorization',
            'token_prefix': 'Splunk ',
            'action_filter': '',
        })
        config.refresh_from_db()
        self.assertEqual(config.get_api_token(), 'new-token')


class ForwarderTests(TestCase):
    """Test the forward_audit_events task."""

    def setUp(self):
        SIEMConfig.objects.all().delete()
        self.config = SIEMConfig.get_config()
        self.config.enabled = True
        self.config.webhook_url = 'https://siem.example/collect'
        self.config.save()
        self.user = User.objects.create_user(username='actor', password='testpass')

    def _make_events(self, count):
        return [AuditLog.objects.create(
            actor=self.user, action='LOGIN', details={'n': i}) for i in range(count)]

    @patch('audit.tasks._post', return_value=True)
    def test_forward_skips_when_disabled(self, mock_post):
        """Disabled config forwards nothing."""
        self.config.enabled = False
        self.config.save()
        self._make_events(3)
        forward_audit_events.run()
        mock_post.assert_not_called()

    @patch('audit.tasks._post', return_value=True)
    def test_forward_posts_above_watermark_in_id_order(self, mock_post):
        """Events above the watermark are posted in id order; watermark advances."""
        events = self._make_events(3)
        self.config.watermark = events[0].pk
        self.config.save()
        forward_audit_events.run()
        # _post receives (config, payload); for Splunk the payload is
        # {'event': ...}. Extract event ids from the payloads.
        posted_ids = []
        for call in mock_post.call_args_list:
            payload = call.args[1]
            if isinstance(payload, dict) and 'event' in payload:
                posted_ids.append(payload['event']['id'])
        self.assertEqual(posted_ids, [e.pk for e in events[1:]])
        self.config.refresh_from_db()
        self.assertEqual(self.config.watermark, events[-1].pk)
        self.assertIsNotNone(self.config.last_success_at)

    @patch('audit.tasks._post', return_value=False)
    def test_failed_post_stops_and_sets_last_error(self, mock_post):
        """A failed POST halts the drain; watermark does not advance."""
        events = self._make_events(3)
        forward_audit_events.run()
        self.config.refresh_from_db()
        self.assertEqual(self.config.watermark, 0)
        self.assertIsNotNone(self.config.last_error)
        self.assertEqual(mock_post.call_count, 1)

    @patch('audit.tasks._post', return_value=True)
    def test_action_filter_applied(self, mock_post):
        """Only actions matching the filter are forwarded."""
        self._make_events(2)
        AuditLog.objects.create(actor=self.user, action='BREAK_GLASS_TRIGGERED')
        self.config.action_filter = 'LOGIN'
        self.config.save()
        forward_audit_events.run()
        self.assertEqual(mock_post.call_count, 2)
        for call in mock_post.call_args_list:
            self.assertEqual(call.args[1]['event']['action'], 'LOGIN')

    @patch('audit.tasks._post', return_value=True)
    def test_backlog_capped_per_run(self, mock_post):
        """At most 200 events are forwarded per run."""
        self._make_events(250)
        forward_audit_events.run()
        self.assertEqual(mock_post.call_count, 200)

    def test_payload_mode_shapes(self):
        """Splunk uses an envelope, Sentinel an array, generic a bare dict."""
        event = {'id': 1, 'action': 'LOGIN'}
        config = SIEMConfig.get_config()
        config.payload_mode = SIEMConfig.PayloadMode.SPLUNK_HEC
        payload = _build_http_payload(config, event)
        self.assertIn('event', payload)
        self.assertEqual(payload['sourcetype'], 'pam:audit')
        config.payload_mode = SIEMConfig.PayloadMode.SENTINEL
        self.assertEqual(_build_http_payload(config, event), [event])
        config.payload_mode = SIEMConfig.PayloadMode.GENERIC
        self.assertEqual(_build_http_payload(config, event), event)

    def test_serialization_shape(self):
        """The serialized event has the expected keys."""
        entry = self._make_events(1)[0]
        event = _serialize_event(entry)
        self.assertEqual(
            set(event.keys()),
            {'id', 'action', 'actor', 'actor_email', 'target_type',
             'target_id', 'details', 'ip_address', 'timestamp'})
        self.assertEqual(event['actor'], 'actor')
        self.assertEqual(event['id'], entry.pk)

    @patch('audit.tasks.urlopen')
    def test_post_sends_auth_header(self, mock_urlopen):
        """The auth header combines token_prefix + token."""
        config = SIEMConfig.get_config()
        config.set_api_token('secret-token')
        config.save()
        mock_resp = MagicMock()
        mock_resp.__enter__.return_value.status = 200
        mock_urlopen.return_value = mock_resp
        self.assertTrue(_post(config, {'event': 'x'}))
        req = mock_urlopen.call_args[0][0]
        self.assertEqual(req.headers['Authorization'], 'Splunk secret-token')

    def test_beat_schedule_registered(self):
        """The forwarder is scheduled in CELERY_BEAT_SCHEDULE."""
        self.assertIn('forward-audit-events', settings.CELERY_BEAT_SCHEDULE)


class LoginLogoutEmissionTests(TestCase):
    """Test LOGIN/LOGOUT audit emissions."""

    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser', password='testpass',
            entra_object_id='oid-123',
        )

    @patch('accounts.backends.EntraOIDCBackend.authenticate')
    def test_oidc_login_emits_audit(self, mock_authenticate):
        """A successful OIDC callback writes a LOGIN row."""
        mock_authenticate.return_value = self.user
        session = self.client.session
        session['oidc_state'] = 'test-state'
        session.save()
        response = self.client.get(reverse('accounts:callback'), {
            'code': 'auth-code',
            'state': 'test-state',
        })
        self.assertRedirects(response, reverse('requests:dashboard'))
        audit = AuditLog.objects.filter(action='LOGIN', actor=self.user).first()
        self.assertIsNotNone(audit)
        self.assertEqual(audit.details['method'], 'oidc')

    def test_local_login_emits_audit(self):
        """A successful local login writes a LOGIN row."""
        response = self.client.post(reverse('accounts:local_login'), {
            'username': 'testuser',
            'password': 'testpass',
        })
        self.assertRedirects(response, reverse('requests:dashboard'))
        audit = AuditLog.objects.filter(action='LOGIN', actor=self.user).first()
        self.assertIsNotNone(audit)
        self.assertEqual(audit.details['method'], 'local')

    def test_logout_emits_audit(self):
        """Logout writes a LOGOUT row with the actor."""
        self.client.force_login(self.user)
        self.client.get(reverse('accounts:logout'))
        self.assertTrue(AuditLog.objects.filter(action='LOGOUT', actor=self.user).exists())


class ActionChoicesTests(TestCase):
    """Test the extended Action choices."""

    def test_admin_revoked_has_display_label(self):
        """ADMIN_REVOKED (emitted by AdminRevokeAccessView) now has a label."""
        entry = AuditLog.objects.create(action='ADMIN_REVOKED')
        self.assertEqual(entry.get_action_display(), 'Access Revoked by Admin')
