"""Tests for rotation plugins and the rotate_entry service."""

import json
from datetime import timedelta
from unittest.mock import MagicMock, patch

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from access_requests.models import AccessRequest
from audit.models import AuditLog
from .models import VaultEntry, VaultRotationEvent
from .rotation import (
    AWSIAMKeyRotationPlugin,
    EntraAppSecretRotationPlugin,
    RotationResult,
    VaultOnlyRotationPlugin,
    rotate_entry,
)
from .crypto import hash_previous_value

User = get_user_model()


def make_entry(**kwargs):
    defaults = dict(
        name='Prod-DB',
        secret_type='API_TOKEN',
        encrypted_value='initial-value',
    )
    defaults.update(kwargs)
    return VaultEntry.objects.create(**defaults)


class RotationPluginTests(TestCase):
    """Unit tests for the plugin implementations."""

    def test_vault_only_rotate_generates_fresh_value(self):
        """The default plugin generates a fresh 24-char value; cleanup no-op."""
        entry = make_entry()
        plugin = VaultOnlyRotationPlugin()
        result = plugin.rotate(entry, 'old')
        self.assertIsNone(result.error)
        self.assertEqual(len(result.new_value), 24)
        self.assertNotEqual(result.new_value, 'old')
        self.assertEqual(plugin.cleanup(entry, 'old', result.new_value, None), (True, None))

    @patch('vault.rotation.boto3.Session')
    def test_aws_rotate_creates_verifies_returns_json_pair(self, mock_session_cls):
        """AWS rotation builds a session from OLD keys, creates + verifies."""
        entry = make_entry(
            rotation_plugin='aws_iam',
            rotation_config={'iam_user_name': 'svc-user', 'region': 'us-west-2'},
            encrypted_value=json.dumps({
                'access_key_id': 'AKIAOLD', 'secret_access_key': 'old-secret'}),
        )
        iam = MagicMock()
        iam.create_access_key.return_value = {'AccessKey': {
            'AccessKeyId': 'AKIANEW', 'SecretAccessKey': 'new-secret'}}
        sts = MagicMock()
        sts.get_caller_identity.return_value = {
            'Arn': 'arn:aws:iam::123456789012:user/svc-user'}
        session = mock_session_cls.return_value
        session.client.side_effect = lambda svc: iam if svc == 'iam' else sts

        result = AWSIAMKeyRotationPlugin().rotate(entry, entry.get_secret_value())
        self.assertIsNone(result.error)
        pair = json.loads(result.new_value)
        self.assertEqual(pair['access_key_id'], 'AKIANEW')
        self.assertEqual(pair['secret_access_key'], 'new-secret')
        iam.create_access_key.assert_called_once_with(UserName='svc-user')
        # Session constructed from the OLD credential
        first_call = mock_session_cls.call_args_list[0].kwargs
        self.assertEqual(first_call['aws_access_key_id'], 'AKIAOLD')
        self.assertEqual(first_call['aws_secret_access_key'], 'old-secret')

    @patch('vault.rotation.boto3.Session')
    def test_aws_rotate_rejects_legacy_plaintext_value(self, mock_session_cls):
        """Legacy plaintext values fail with a clear message; no AWS call."""
        entry = make_entry(
            rotation_plugin='aws_iam',
            rotation_config={'iam_user_name': 'svc-user'},
            encrypted_value='legacy-plaintext-key',
        )
        result = AWSIAMKeyRotationPlugin().rotate(entry, 'legacy-plaintext-key')
        self.assertIsNotNone(result.error)
        self.assertIn('not a valid AWS key pair JSON', result.error)
        mock_session_cls.assert_not_called()

    @patch('vault.rotation.boto3.Session')
    def test_aws_rotate_verify_failure_revokes_new_key(self, mock_session_cls):
        """A failed verification deletes the just-created key."""
        entry = make_entry(
            rotation_plugin='aws_iam',
            rotation_config={'iam_user_name': 'svc-user', 'region': 'us-east-1'},
            encrypted_value=json.dumps({
                'access_key_id': 'AKIAOLD', 'secret_access_key': 'old-secret'}),
        )
        iam = MagicMock()
        iam.create_access_key.return_value = {'AccessKey': {
            'AccessKeyId': 'AKIANEW', 'SecretAccessKey': 'new-secret'}}
        sts = MagicMock()
        sts.get_caller_identity.side_effect = Exception('boom')
        session = mock_session_cls.return_value
        session.client.side_effect = lambda svc: iam if svc == 'iam' else sts

        result = AWSIAMKeyRotationPlugin().rotate(entry, entry.get_secret_value())
        self.assertIsNotNone(result.error)
        self.assertIsNone(result.new_value)
        self.assertIn('failed verification', result.error)
        iam.delete_access_key.assert_called_once_with(
            UserName='svc-user', AccessKeyId='AKIANEW')

    @patch('vault.rotation.boto3.Session')
    def test_aws_rotate_limit_exceeded_returns_clear_error(self, mock_session_cls):
        """The two-keys cap produces an actionable message."""
        entry = make_entry(
            rotation_plugin='aws_iam',
            rotation_config={'iam_user_name': 'svc-user'},
            encrypted_value=json.dumps({
                'access_key_id': 'AKIAOLD', 'secret_access_key': 'old-secret'}),
        )
        iam = MagicMock()
        from botocore.exceptions import ClientError
        iam.create_access_key.side_effect = ClientError(
            {'Error': {'Code': 'LimitExceeded', 'Message': 'max keys'}}, 'CreateAccessKey')
        session = mock_session_cls.return_value
        session.client.return_value = iam

        result = AWSIAMKeyRotationPlugin().rotate(entry, entry.get_secret_value())
        self.assertIn('two access keys', result.error)

    @patch('vault.rotation.boto3.Session')
    def test_aws_cleanup_deletes_old_key(self, mock_session_cls):
        """Cleanup deletes the OLD key with the old credential."""
        entry = make_entry(
            rotation_plugin='aws_iam',
            rotation_config={'iam_user_name': 'svc-user', 'region': 'us-east-1'},
            encrypted_value=json.dumps({
                'access_key_id': 'AKIAOLD', 'secret_access_key': 'old-secret'}),
        )
        iam = MagicMock()
        session = mock_session_cls.return_value
        session.client.return_value = iam
        ok, err = AWSIAMKeyRotationPlugin().cleanup(
            entry, entry.get_secret_value(), '{"access_key_id": "AKIANEW"}')
        self.assertTrue(ok)
        self.assertIsNone(err)
        iam.delete_access_key.assert_called_once_with(
            UserName='svc-user', AccessKeyId='AKIAOLD')

    @patch('vault.rotation.msal.ConfidentialClientApplication')
    @patch('vault.rotation.httpx.request')
    def test_entra_rotate_adds_secret_and_captures_keyid(self, mock_http, mock_msal):
        """Entra rotation captures secretText + keyId and passes old keyId to cleanup."""
        entry = make_entry(
            rotation_plugin='entra_app_secret',
            rotation_config={'tenant_id': 't-1', 'client_id': 'c-1'},
            rotation_state={'entra_key_id': 'k-old'},
            encrypted_value='current-secret',
        )
        mock_msal.return_value.acquire_token_for_client.return_value = {
            'access_token': 'token-1'}
        mock_http.return_value.status_code = 200
        mock_http.return_value.json.return_value = {
            'secretText': 'new-secret', 'keyId': 'k-new'}

        result = EntraAppSecretRotationPlugin().rotate(entry, 'current-secret')
        self.assertIsNone(result.error)
        self.assertEqual(result.new_value, 'new-secret')
        self.assertEqual(result.state, {'entra_key_id': 'k-new'})
        self.assertEqual(result.cleanup_context, {'old_key_id': 'k-old'})
        body = mock_http.call_args.kwargs['json']
        self.assertIn('endDateTime', body['passwordCredential'])

    @patch('vault.rotation.msal.ConfidentialClientApplication')
    @patch('vault.rotation.httpx.request')
    def test_entra_rotate_token_failure_returns_error(self, mock_http, mock_msal):
        """Token failure surfaces the error without any HTTP call."""
        entry = make_entry(
            rotation_plugin='entra_app_secret',
            rotation_config={'tenant_id': 't-1', 'client_id': 'c-1'},
            encrypted_value='current-secret',
        )
        mock_msal.return_value.acquire_token_for_client.return_value = {
            'error': 'invalid_client', 'error_description': 'bad secret'}
        result = EntraAppSecretRotationPlugin().rotate(entry, 'current-secret')
        self.assertIsNotNone(result.error)
        self.assertIn('bad secret', result.error)
        mock_http.assert_not_called()

    @patch('vault.rotation.msal.ConfidentialClientApplication')
    @patch('vault.rotation.httpx.request')
    def test_entra_cleanup_removes_old_keyid(self, mock_http, mock_msal):
        """Cleanup posts removePassword with the captured old keyId."""
        entry = make_entry(
            rotation_plugin='entra_app_secret',
            rotation_config={'tenant_id': 't-1', 'client_id': 'c-1'},
        )
        mock_msal.return_value.acquire_token_for_client.return_value = {
            'access_token': 'token-2'}
        mock_http.return_value.status_code = 204
        ok, err = EntraAppSecretRotationPlugin().cleanup(
            entry, 'old-secret', 'new-secret', {'old_key_id': 'k-old'})
        self.assertTrue(ok)
        body = mock_http.call_args.kwargs['json']
        self.assertEqual(body, {'keyId': 'k-old'})

    @patch('vault.rotation.msal.ConfidentialClientApplication')
    @patch('vault.rotation.httpx.request')
    def test_entra_cleanup_unknown_old_keyid_skips_with_warning(self, mock_http, mock_msal):
        """Legacy entries without a recorded keyId warn instead of guessing."""
        entry = make_entry(
            rotation_plugin='entra_app_secret',
            rotation_config={'tenant_id': 't-1', 'client_id': 'c-1'},
            rotation_state={'entra_key_id': 'k-new'},
        )
        mock_msal.return_value.acquire_token_for_client.return_value = {
            'access_token': 'token-2'}
        mock_http.return_value.status_code = 200
        mock_http.return_value.json.return_value = {'value': []}
        ok, err = EntraAppSecretRotationPlugin().cleanup(
            entry, 'old-secret', 'new-secret', {'old_key_id': None})
        self.assertFalse(ok)
        self.assertIn('manually', err)


class RotateEntryServiceTests(TestCase):
    """Test the rotate_entry service end-to-end."""

    def test_rotate_entry_plugin_success_stores_audits_and_cleans(self):
        """Success stores the value, merges state, records synced event + audit."""
        entry = make_entry(rotation_plugin='aws_iam',
                           rotation_config={'iam_user_name': 'svc-user'})
        plugin = AWSIAMKeyRotationPlugin()
        with patch('vault.rotation.AWSIAMKeyRotationPlugin.rotate') as mock_rotate, \
             patch('vault.rotation.AWSIAMKeyRotationPlugin.cleanup', return_value=(True, None)) as mock_cleanup:
            mock_rotate.return_value = RotationResult(
                new_value='{"access_key_id": "AKIANEW", "secret_access_key": "s"}',
                state={'iam_user_name': 'svc-user'})
            ok, err = rotate_entry(entry, VaultRotationEvent.Reason.MANUAL,
                                   user=None)
        self.assertTrue(ok)
        self.assertIsNone(err)
        entry.refresh_from_db()
        self.assertEqual(entry.rotation_state, {'iam_user_name': 'svc-user'})
        event = entry.rotation_events.get()
        self.assertEqual(event.plugin, 'aws_iam')
        self.assertTrue(event.synced_to_system)
        mock_cleanup.assert_called_once()
        audit = AuditLog.objects.filter(action='VAULT_SECRET_ROTATED').first()
        self.assertTrue(audit.details['synced'])

    def test_rotate_entry_plugin_failure_keeps_old_value_and_records_error(self):
        """Failure keeps the old value; a synced=False event records the error."""
        entry = make_entry(rotation_plugin='aws_iam',
                           rotation_config={'iam_user_name': 'svc-user'})
        old = entry.get_secret_value()
        with patch('vault.rotation.AWSIAMKeyRotationPlugin.rotate') as mock_rotate, \
             patch('vault.rotation.AWSIAMKeyRotationPlugin.cleanup') as mock_cleanup:
            mock_rotate.return_value = RotationResult(error='AWS API down')
            ok, err = rotate_entry(entry, VaultRotationEvent.Reason.AUTO_CHECKIN)
        self.assertFalse(ok)
        self.assertEqual(err, 'AWS API down')
        entry.refresh_from_db()
        self.assertEqual(entry.get_secret_value(), old)
        event = entry.rotation_events.get()
        self.assertFalse(event.synced_to_system)
        self.assertEqual(event.error, 'AWS API down')
        mock_cleanup.assert_not_called()
        audit = AuditLog.objects.filter(action='VAULT_SECRET_ROTATED').first()
        self.assertFalse(audit.details['synced'])

    def test_rotate_entry_cleanup_failure_still_ok(self):
        """A cleanup failure records the error but the rotation succeeds."""
        entry = make_entry(rotation_plugin='aws_iam',
                           rotation_config={'iam_user_name': 'svc-user'})
        with patch('vault.rotation.AWSIAMKeyRotationPlugin.rotate') as mock_rotate, \
             patch('vault.rotation.AWSIAMKeyRotationPlugin.cleanup', return_value=(False, 'delete failed')) as mock_cleanup:
            mock_rotate.return_value = RotationResult(
                new_value='{"access_key_id": "AKIANEW", "secret_access_key": "s"}')
            ok, err = rotate_entry(entry, VaultRotationEvent.Reason.MANUAL)
        self.assertTrue(ok)
        self.assertIsNone(err)
        event = entry.rotation_events.get()
        self.assertTrue(event.synced_to_system)
        self.assertEqual(event.error, 'delete failed')

    def test_rotate_entry_explicit_value_rejected_on_plugin_entry(self):
        """Typed values are rejected for plugin-managed entries."""
        entry = make_entry(rotation_plugin='aws_iam',
                           rotation_config={'iam_user_name': 'svc-user'})
        with patch('vault.rotation.AWSIAMKeyRotationPlugin.rotate') as mock_rotate:
            ok, err = rotate_entry(entry, VaultRotationEvent.Reason.MANUAL,
                                   explicit_value='typed')
        self.assertFalse(ok)
        self.assertIn('plugin-managed', err)
        mock_rotate.assert_not_called()

    def test_rotate_entry_reuse_checks_shared_by_both_paths(self):
        """Same-value and previously-used rejections preserve exact messages."""
        entry = make_entry()
        ok, err = rotate_entry(entry, VaultRotationEvent.Reason.MANUAL,
                               explicit_value='initial-value')
        self.assertFalse(ok)
        self.assertEqual(err, 'The new value is identical to the current value.')
        self.assertEqual(entry.rotation_events.count(), 0)
        # Rotate once, then reuse the original
        self.assertTrue(rotate_entry(
            entry, VaultRotationEvent.Reason.MANUAL, explicit_value='second')[0])
        ok, err = rotate_entry(entry, VaultRotationEvent.Reason.MANUAL,
                               explicit_value='initial-value')
        self.assertFalse(ok)
        self.assertEqual(err, 'That value was previously used for this entry.')

    def test_rotate_entry_unknown_plugin_fails_gracefully(self):
        """Unknown plugin names fail cleanly with a recorded event."""
        entry = make_entry(rotation_plugin='nope')
        ok, err = rotate_entry(entry, VaultRotationEvent.Reason.MANUAL)
        self.assertFalse(ok)
        self.assertIn('Unknown rotation plugin', err)
        event = entry.rotation_events.get()
        self.assertFalse(event.synced_to_system)


class RotationWiringTests(TestCase):
    """Test the provider and view wiring."""

    def setUp(self):
        self.staff = User.objects.create_user(
            username='staff', password='testpass', is_staff=True)

    @patch('vault.rotation.AWSIAMKeyRotationPlugin.rotate')
    @patch('vault.rotation.AWSIAMKeyRotationPlugin.cleanup', return_value=(True, None))
    def test_deprovision_plugin_entry_rotates_via_plugin(self, mock_cleanup, mock_rotate):
        """Check-in on an auto-rotate plugin entry rotates through the plugin."""
        entry = make_entry(
            auto_rotate=True, rotation_plugin='aws_iam',
            rotation_config={'iam_user_name': 'svc-user'},
            encrypted_value=json.dumps({
                'access_key_id': 'AKIAOLD', 'secret_access_key': 'old-secret'}),
        )
        mock_rotate.return_value = RotationResult(
            new_value='{"access_key_id": "AKIANEW", "secret_access_key": "s"}')
        from vault.provider import VaultProvider
        self.assertTrue(VaultProvider().deprovision_access(f'vault:{entry.pk}'))
        event = entry.rotation_events.get()
        self.assertEqual(event.reason, VaultRotationEvent.Reason.AUTO_CHECKIN)
        self.assertEqual(event.plugin, 'aws_iam')
        self.assertTrue(event.synced_to_system)

    @patch('vault.rotation.AWSIAMKeyRotationPlugin.rotate')
    def test_deprovision_rotation_failure_still_returns_true(self, mock_rotate):
        """A failed rotation never wedges the deprovision pipeline."""
        entry = make_entry(
            auto_rotate=True, rotation_plugin='aws_iam',
            rotation_config={'iam_user_name': 'svc-user'})
        old = entry.get_secret_value()
        mock_rotate.return_value = RotationResult(error='boom')
        from vault.provider import VaultProvider
        self.assertTrue(VaultProvider().deprovision_access(f'vault:{entry.pk}'))
        entry.refresh_from_db()
        self.assertEqual(entry.get_secret_value(), old)
        self.assertFalse(entry.rotation_events.get().synced_to_system)

    @patch('vault.rotation.AWSIAMKeyRotationPlugin.rotate')
    @patch('vault.rotation.AWSIAMKeyRotationPlugin.cleanup', return_value=(True, None))
    def test_manual_rotate_plugin_entry_ignores_posted_value(self, mock_cleanup, mock_rotate):
        """Staff rotate on a plugin entry is plugin-driven; typed value ignored."""
        entry = make_entry(
            rotation_plugin='aws_iam',
            rotation_config={'iam_user_name': 'svc-user'},
            encrypted_value=json.dumps({
                'access_key_id': 'AKIAOLD', 'secret_access_key': 'old-secret'}),
        )
        mock_rotate.return_value = RotationResult(
            new_value='{"access_key_id": "AKIANEW", "secret_access_key": "s"}')
        self.client.force_login(self.staff)
        response = self.client.post(
            reverse('vault:rotate', kwargs={'pk': entry.pk}),
            {'new_value': 'ignored'})
        self.assertRedirects(response, reverse('vault:detail', kwargs={'pk': entry.pk}))
        entry.refresh_from_db()
        self.assertNotEqual(entry.get_secret_value(), 'ignored')
        event = entry.rotation_events.get()
        self.assertEqual(event.reason, VaultRotationEvent.Reason.MANUAL)
        self.assertEqual(event.rotated_by, self.staff)

    @patch('vault.rotation.AWSIAMKeyRotationPlugin.rotate')
    def test_manual_rotate_plugin_failure_message_and_value_kept(self, mock_rotate):
        """Plugin failure on manual rotate keeps the value and shows the error."""
        entry = make_entry(
            rotation_plugin='aws_iam',
            rotation_config={'iam_user_name': 'svc-user'})
        old = entry.get_secret_value()
        mock_rotate.return_value = RotationResult(error='target unreachable')
        self.client.force_login(self.staff)
        response = self.client.post(
            reverse('vault:rotate', kwargs={'pk': entry.pk}))
        entry.refresh_from_db()
        self.assertEqual(entry.get_secret_value(), old)
        from django.contrib.messages import get_messages
        messages = [str(m) for m in get_messages(response.wsgi_request)]
        self.assertTrue(any('Rotation failed' in m for m in messages))


class RotationFormTests(TestCase):
    """Test the rotation fields on the entry form."""

    def test_form_rejects_invalid_header_lines(self):
        """Malformed header lines fail validation on the structured field."""
        from .forms import VaultEntryForm
        form = VaultEntryForm(data={
            'name': 'X', 'secret_type': 'PASSWORD', 'value': 'v',
            'rotation_plugin': 'http', 'url': 'https://example/api',
            'headers': 'no-colon-here',
        })
        self.assertFalse(form.is_valid())
        self.assertIn('headers', form.errors)

    def test_form_requires_plugin_config_keys(self):
        """Plugins require their config keys (errors on the structured field)."""
        from .forms import VaultEntryForm
        base = {'name': 'X', 'secret_type': 'PASSWORD', 'value': 'v',
                    'max_checkout_minutes': '60'}
        aws = VaultEntryForm(data={**base, 'rotation_plugin': 'aws_iam'})
        self.assertFalse(aws.is_valid())
        self.assertIn('iam_user_name', aws.errors)
        entra = VaultEntryForm(data={**base, 'rotation_plugin': 'entra_app_secret',
                                     'tenant_id': 't'})
        self.assertFalse(entra.is_valid())
        self.assertIn('client_id', entra.errors)

    def test_form_builds_config_only_from_selected_plugin(self):
        """Stray values from other plugins are not stored in rotation_config."""
        from .forms import VaultEntryForm
        form = VaultEntryForm(data={
            'name': 'X', 'secret_type': 'PASSWORD', 'value': 'v',
            'max_checkout_minutes': '60',
            'rotation_plugin': 'postgresql',
            'host': 'db1', 'username': 'app', 'port': '5432',
            'iam_user_name': 'stray-value',  # belongs to another plugin
        })
        self.assertTrue(form.is_valid(), form.errors)
        config = form.cleaned_data['rotation_config']
        self.assertEqual(set(config.keys()), {'host', 'username', 'port'})

    def test_form_initializes_structured_fields_from_instance_config(self):
        """Editing an existing entry prefills the structured fields."""
        from .forms import VaultEntryForm
        entry = make_entry(rotation_plugin='postgresql',
                           rotation_config={'host': 'db1', 'username': 'app',
                                            'port': 5432, 'dbname': 'appdb'})
        form = VaultEntryForm(instance=entry)
        self.assertEqual(form.fields['host'].initial, 'db1')
        self.assertEqual(form.fields['username'].initial, 'app')
        self.assertEqual(form.fields['port'].initial, 5432)
        self.assertEqual(form.fields['dbname'].initial, 'appdb')

    def test_header_lines_round_trip(self):
        """Header 'Name: value' lines parse and format back."""
        from .forms import format_header_lines, parse_header_lines
        headers = parse_header_lines('Authorization: Bearer abc\nX-Key: v')
        self.assertEqual(headers, {'Authorization': 'Bearer abc', 'X-Key': 'v'})
        self.assertEqual(
            format_header_lines(headers), 'Authorization: Bearer abc\nX-Key: v')

    def test_create_view_persists_plugin_fields(self):
        """Staff create persists plugin + structured config."""
        from .forms import VaultEntryForm
        staff = User.objects.create_user(username='s2', password='x', is_staff=True)
        self.client.force_login(staff)
        response = self.client.post(reverse('vault:create'), {
            'name': 'Plugin-Entry',
            'secret_type': 'API_TOKEN',
            'value': 'current-live-secret',
            'auto_rotate': 'on',
            'requires_approval': 'on',
            'max_checkout_minutes': '60',
            'rotation_plugin': 'aws_iam',
            'iam_user_name': 'svc-user',
            'region': 'us-east-1',
        })
        self.assertRedirects(response, reverse('vault:list'))
        entry = VaultEntry.objects.get(name='Plugin-Entry')
        self.assertEqual(entry.rotation_plugin, 'aws_iam')
        self.assertEqual(entry.rotation_config['iam_user_name'], 'svc-user')
        self.assertEqual(entry.rotation_config['region'], 'us-east-1')
        self.assertEqual(entry.get_secret_value(), 'current-live-secret')
