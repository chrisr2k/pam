"""Tests for the remaining rotation plugins (ssh, postgresql, mysql, winrm, http)."""

import string
from unittest.mock import MagicMock, patch

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

from .crypto import generate_rotation_value, hash_previous_value
from .models import VaultEntry, VaultRotationEvent
from .rotation import (
    GenericHTTPRotationPlugin,
    MySQLPasswordRotationPlugin,
    PostgreSQLPasswordRotationPlugin,
    RotationResult,
    SSHPasswordRotationPlugin,
    WinRMPasswordRotationPlugin,
    plugin_choices,
    rotate_entry,
)

User = get_user_model()


def make_entry(**kwargs):
    defaults = dict(name='Prod-DB', secret_type='PASSWORD', encrypted_value='initial-value')
    defaults.update(kwargs)
    return VaultEntry.objects.create(**defaults)


class SSHRotationPluginTests(TestCase):
    """SSH plugin: stdin chpasswd, sudo, auth failure, rollback."""

    def _entry(self, **cfg_overrides):
        cfg = {'host': 'srv1', 'username': 'appuser', 'use_sudo': False}
        cfg.update(cfg_overrides)
        return make_entry(rotation_plugin='ssh', rotation_config=cfg,
                          encrypted_value='oldpass')

    def _mock_client(self, exec_factory):
        """Build an SSHClient mock whose exec_command returns exec_factory()."""
        client = MagicMock()
        stdin = MagicMock()
        stdout = MagicMock()
        stderr = MagicMock()
        stdout.channel.recv_exit_status.return_value = 0
        stdout.read.return_value = b'appuser\n'
        stdin.channel.shutdown_write.return_value = None
        client.exec_command.side_effect = lambda *a, **k: exec_factory(
            stdin, stdout, stderr, *a, **k)
        return client

    @patch('vault.rotation.paramiko.SSHClient')
    def test_ssh_rotate_sets_password_and_verifies(self, mock_ssh_cls):
        """No sudo: chpasswd via stdin; verify connect runs whoami."""
        writes = []

        def exec_factory(stdin, stdout, stderr, command, **kwargs):
            if command == 'chpasswd':
                stdin.write.side_effect = lambda data: writes.append(data)
            return stdin, stdout, stderr

        apply_client = self._mock_client(exec_factory)
        verify_client = self._mock_client(exec_factory)
        mock_ssh_cls.side_effect = [apply_client, verify_client]

        entry = self._entry()
        result = SSHPasswordRotationPlugin().rotate(entry, 'oldpass', candidate='NewPass1!')
        self.assertIsNone(result.error)
        self.assertEqual(result.new_value, 'NewPass1!')
        self.assertIn('appuser:NewPass1!\n', writes)
        # Second connection (verify) authenticated with the new password
        self.assertEqual(verify_client.connect.call_args.kwargs['password'], 'NewPass1!')

    @patch('vault.rotation.paramiko.SSHClient')
    def test_ssh_rotate_sudo_writes_sudo_password_then_chpasswd_line(self, mock_ssh_cls):
        """Sudo: get_pty, sudo password line first, then user:new."""
        writes = []
        commands = []

        def exec_factory(stdin, stdout, stderr, command, **kwargs):
            commands.append(command)
            stdin.write.side_effect = lambda data: writes.append(data)
            return stdin, stdout, stderr

        mock_ssh_cls.side_effect = [self._mock_client(exec_factory),
                                    self._mock_client(exec_factory)]

        entry = self._entry(use_sudo=True)
        result = SSHPasswordRotationPlugin().rotate(entry, 'oldpass', candidate='NewPass1!')
        self.assertIsNone(result.error)
        self.assertEqual(commands[0], 'sudo -S chpasswd')
        self.assertEqual(commands[-1], 'whoami')
        self.assertEqual(writes[0], 'oldpass\n')
        self.assertEqual(writes[1], 'appuser:NewPass1!\n')

    @patch('vault.rotation.paramiko.SSHClient')
    def test_ssh_rotate_auth_failure_returns_error(self, mock_ssh_cls):
        """Authentication failure surfaces a clear error; no exec."""
        mock_ssh_cls.return_value.connect.side_effect = (
            __import__('paramiko').AuthenticationException('denied'))
        entry = self._entry()
        result = SSHPasswordRotationPlugin().rotate(entry, 'oldpass', candidate='NewPass1!')
        self.assertIsNotNone(result.error)
        self.assertIn('old credential rejected', result.error)
        mock_ssh_cls.return_value.exec_command.assert_not_called()

    @patch('vault.rotation.paramiko.SSHClient')
    def test_ssh_rotate_verify_failure_rolls_back_old_password(self, mock_ssh_cls):
        """Verify failure re-applies the old password and reports it."""
        writes = []

        def exec_factory(stdin, stdout, stderr, command, **kwargs):
            stdin.write.side_effect = lambda data: writes.append(data)
            return stdin, stdout, stderr

        apply_client = self._mock_client(exec_factory)
        mock_ssh_cls.side_effect = [
            apply_client,               # initial apply
            __import__('paramiko').AuthenticationException('denied'),  # verify fails
            self._mock_client(exec_factory),  # rollback connect (with new)
        ]

        entry = self._entry()
        result = SSHPasswordRotationPlugin().rotate(entry, 'oldpass', candidate='NewPass1!')
        self.assertIsNotNone(result.error)
        self.assertIn('failed verification', result.error)
        # Rollback wrote the OLD password back
        self.assertTrue(any('appuser:oldpass\n' == w for w in writes))


class PostgreSQLRotationPluginTests(TestCase):
    """PostgreSQL plugin: ALTER + bind param, auth failure, rollback."""

    def _entry(self):
        return make_entry(rotation_plugin='postgresql',
                          rotation_config={'host': 'db1', 'username': 'app'},
                          encrypted_value='oldpass')

    @patch('vault.rotation.psycopg2.connect')
    def test_postgresql_rotate_alters_password_and_verifies(self, mock_connect):
        """ALTER USER with Identifier + bind param; verify connect SELECT 1."""
        apply_conn = MagicMock()
        apply_conn.autocommit = True
        verify_conn = MagicMock()
        mock_connect.side_effect = [apply_conn, verify_conn]

        entry = self._entry()
        result = PostgreSQLPasswordRotationPlugin().rotate(
            entry, 'oldpass', candidate='NewPass1!')
        self.assertIsNone(result.error)
        self.assertEqual(result.new_value, 'NewPass1!')
        execute = apply_conn.cursor.return_value.execute
        self.assertTrue(execute.called)
        sql, params = execute.call_args[0]
        self.assertIn('ALTER USER', str(sql))
        self.assertIn('app', str(sql))
        self.assertEqual(params, ('NewPass1!',))
        verify_execute = verify_conn.cursor.return_value.execute
        verify_execute.assert_called_once_with('SELECT 1')

    @patch('vault.rotation.psycopg2.connect')
    def test_postgresql_rotate_auth_failure_returns_error(self, mock_connect):
        """Auth failures get the dedicated message."""
        import psycopg2
        mock_connect.side_effect = psycopg2.OperationalError(
            'FATAL: password authentication failed for user "app"')
        entry = self._entry()
        result = PostgreSQLPasswordRotationPlugin().rotate(
            entry, 'oldpass', candidate='NewPass1!')
        self.assertIn('old credential rejected', result.error)

    @patch('vault.rotation.psycopg2.connect')
    def test_postgresql_rotate_verify_failure_rolls_back_on_open_connection(self, mock_connect):
        """Verify failure re-runs ALTER with the old value on the open conn."""
        apply_conn = MagicMock()
        apply_conn.autocommit = True
        mock_connect.side_effect = [apply_conn, Exception('verify failed')]

        entry = self._entry()
        result = PostgreSQLPasswordRotationPlugin().rotate(
            entry, 'oldpass', candidate='NewPass1!')
        self.assertIsNotNone(result.error)
        self.assertIn('failed verification', result.error)
        execute = apply_conn.cursor.return_value.execute
        self.assertEqual(execute.call_args[0][1], ('oldpass',))


class MySQLPasswordRotationPluginTests(TestCase):
    """MySQL plugin: escaping, NO_BACKSLASH_ESCAPES, validation, auth."""

    def _entry(self, **cfg_overrides):
        cfg = {'host': 'db1', 'username': 'app', 'host_part': '%'}
        cfg.update(cfg_overrides)
        return make_entry(rotation_plugin='mysql', rotation_config=cfg,
                          encrypted_value='oldpass')

    def _conn(self, sql_mode=''):
        conn = MagicMock()
        cursor = MagicMock()
        cursor.__enter__.return_value = cursor
        cursor.fetchone.return_value = (sql_mode,)
        conn.cursor.return_value = cursor
        return conn

    @patch('vault.rotation.pymysql.connect')
    def test_mysql_rotate_alters_password_and_verifies(self, mock_connect):
        """ALTER USER with escaped candidate; verify connect SELECT 1."""
        apply_conn = self._conn()
        verify_conn = self._conn()
        mock_connect.side_effect = [apply_conn, verify_conn]

        entry = self._entry()
        result = MySQLPasswordRotationPlugin().rotate(
            entry, 'oldpass', candidate="New'Pass\\1!")
        self.assertIsNone(result.error)
        execute = apply_conn.cursor.return_value.__enter__.return_value.execute
        sql = execute.call_args[0][0]
        self.assertIn("ALTER USER 'app'@'%' IDENTIFIED BY", sql)
        self.assertNotIn("New'Pass\\1!", sql)  # raw value never in SQL
        verify_execute = verify_conn.cursor.return_value.__enter__.return_value.execute
        verify_execute.assert_called_once_with('SELECT 1')

    @patch('vault.rotation.pymysql.connect')
    def test_mysql_rotate_doubles_quotes_under_no_backslash_escapes(self, mock_connect):
        """NO_BACKSLASH_ESCAPES switches to quote-doubling."""
        apply_conn = self._conn(sql_mode='NO_BACKSLASH_ESCAPES')
        mock_connect.side_effect = [apply_conn, self._conn()]

        entry = self._entry()
        result = MySQLPasswordRotationPlugin().rotate(
            entry, 'oldpass', candidate="a'b")
        self.assertIsNone(result.error)
        sql = apply_conn.cursor.return_value.__enter__.return_value.execute.call_args[0][0]
        self.assertIn("IDENTIFIED BY 'a''b'", sql)

    def test_mysql_rotate_rejects_unsafe_username_or_host_part(self):
        """Unsafe identifiers are rejected before any connection."""
        result = MySQLPasswordRotationPlugin().rotate(
            self._entry(username="bad'user"), 'oldpass', candidate='NewPass1!')
        self.assertIsNotNone(result.error)
        result = MySQLPasswordRotationPlugin().rotate(
            self._entry(host_part='bad;host'), 'oldpass', candidate='NewPass1!')
        self.assertIsNotNone(result.error)

    @patch('vault.rotation.pymysql.connect')
    def test_mysql_rotate_auth_failure_returns_error(self, mock_connect):
        """Access denied (1045) gets the dedicated message."""
        import pymysql
        mock_connect.side_effect = pymysql.err.OperationalError(1045, 'Access denied')
        entry = self._entry()
        result = MySQLPasswordRotationPlugin().rotate(
            entry, 'oldpass', candidate='NewPass1!')
        self.assertIn('old credential rejected', result.error)


class WinRMPasswordRotationPluginTests(TestCase):
    """WinRM plugin: quote-free generation, scripts, failures."""

    def _entry(self, **cfg_overrides):
        cfg = {'host': 'win1', 'username': 'svcuser'}
        cfg.update(cfg_overrides)
        return make_entry(rotation_plugin='winrm', rotation_config=cfg,
                          encrypted_value='oldpass')

    def test_winrm_generate_value_excludes_quotes(self):
        """Generated values never contain quotes; all classes present."""
        import string
        plugin = WinRMPasswordRotationPlugin()
        for _ in range(50):
            value = plugin.generate_value()
            self.assertEqual(len(value), 24)
            self.assertNotIn("'", value)
            self.assertNotIn('"', value)
            self.assertTrue(any(c.isupper() for c in value))
            self.assertTrue(any(c.islower() for c in value))
            self.assertTrue(any(c.isdigit() for c in value))
            self.assertTrue(any(c in string.punctuation for c in value))

    @patch('vault.rotation.winrm.Session')
    def test_winrm_rotate_local_account_changes_password_and_verifies(self, mock_session_cls):
        """Local account: net user script; verify session runs whoami."""
        apply_session = MagicMock()
        apply_session.run_cmd.return_value.status_code = 0
        verify_session = MagicMock()
        verify_session.run_cmd.return_value.status_code = 0
        mock_session_cls.side_effect = [apply_session, verify_session]

        entry = self._entry()
        result = WinRMPasswordRotationPlugin().rotate(
            entry, 'oldpass', candidate='NewPass1!')
        self.assertIsNone(result.error)
        self.assertEqual(result.new_value, 'NewPass1!')
        script = apply_session.run_cmd.call_args[0][1][2]
        self.assertIn('net user', script)
        self.assertIn('NewPass1!', script)

    @patch('vault.rotation.winrm.Session')
    def test_winrm_rotate_ad_account_uses_set_adaccountpassword(self, mock_session_cls):
        """AD account type uses Set-ADAccountPassword."""
        apply_session = MagicMock()
        apply_session.run_cmd.return_value.status_code = 0
        verify_session = MagicMock()
        verify_session.run_cmd.return_value.status_code = 0
        mock_session_cls.side_effect = [apply_session, verify_session]

        entry = self._entry(account_type='ad')
        result = WinRMPasswordRotationPlugin().rotate(
            entry, 'oldpass', candidate='NewPass1!')
        self.assertIsNone(result.error)
        script = apply_session.run_cmd.call_args[0][1][2]
        self.assertIn('Set-ADAccountPassword', script)

    @patch('vault.rotation.winrm.Session')
    def test_winrm_rotate_command_failure_returns_error(self, mock_session_cls):
        """A non-zero status code fails with the old password kept."""
        apply_session = MagicMock()
        apply_session.run_cmd.return_value.status_code = 1
        mock_session_cls.return_value = apply_session

        entry = self._entry()
        result = WinRMPasswordRotationPlugin().rotate(
            entry, 'oldpass', candidate='NewPass1!')
        self.assertIsNotNone(result.error)
        self.assertIn('command failed', result.error)


class GenericHTTPRotationPluginTests(TestCase):
    """HTTP plugin: templating, status checks, verify, cleanup."""

    def _entry(self, **cfg_overrides):
        cfg = {'url': 'https://api.example/rotate', 'body_template': '{"pw": "{new_value}"}'}
        cfg.update(cfg_overrides)
        return make_entry(rotation_plugin='http', rotation_config=cfg,
                          encrypted_value='oldpass')

    @patch('vault.rotation.requests.request')
    def test_http_rotate_posts_rendered_body_and_checks_status(self, mock_request):
        """Rendered body/headers posted; 200 accepts."""
        mock_request.return_value.status_code = 200
        entry = self._entry(headers={'X-Old': '{old_value}'})
        result = GenericHTTPRotationPlugin().rotate(
            entry, 'oldpass', candidate='NewPass1!')
        self.assertIsNone(result.error)
        self.assertEqual(result.new_value, 'NewPass1!')
        kwargs = mock_request.call_args.kwargs
        self.assertEqual(kwargs['data'], '{"pw": "NewPass1!"}')
        self.assertEqual(kwargs['headers']['X-Old'], 'oldpass')

    @patch('vault.rotation.requests.request')
    def test_http_rotate_bad_status_returns_error_no_verify(self, mock_request):
        """A 500 fails without any verify request."""
        mock_request.return_value.status_code = 500
        entry = self._entry(verify_url='https://api.example/verify')
        result = GenericHTTPRotationPlugin().rotate(
            entry, 'oldpass', candidate='NewPass1!')
        self.assertIsNotNone(result.error)
        self.assertIn('status 500', result.error)
        self.assertEqual(mock_request.call_count, 1)

    @patch('vault.rotation.requests.request')
    def test_http_rotate_verify_url_failure_returns_error(self, mock_request):
        """Verify failure mentions manual reconciliation."""
        mock_request.side_effect = [MagicMock(status_code=200), MagicMock(status_code=401)]
        entry = self._entry(verify_url='https://api.example/verify')
        result = GenericHTTPRotationPlugin().rotate(
            entry, 'oldpass', candidate='NewPass1!')
        self.assertIsNotNone(result.error)
        self.assertIn('reconcile manually', result.error)

    @patch('vault.rotation.requests.request')
    def test_http_cleanup_posts_cleanup_url_else_noop(self, mock_request):
        """cleanup_url configured → request; absent → no-op."""
        mock_request.return_value.status_code = 200
        entry = self._entry(cleanup_url='https://api.example/cleanup')
        ok, err = GenericHTTPRotationPlugin().cleanup(entry, 'old', 'new')
        self.assertTrue(ok)
        self.assertEqual(mock_request.call_count, 1)
        entry2 = self._entry()
        ok, err = GenericHTTPRotationPlugin().cleanup(entry2, 'old', 'new')
        self.assertTrue(ok)
        self.assertEqual(mock_request.call_count, 1)

    @patch('vault.rotation.requests.request')
    def test_http_templating_is_literal_not_str_format(self, mock_request):
        """JSON braces survive; only the tokens are replaced."""
        mock_request.return_value.status_code = 200
        entry = self._entry(body_template='{"a": 1, "pw": "{new_value}"}')
        GenericHTTPRotationPlugin().rotate(entry, 'oldpass', candidate='NewPass1!')
        self.assertEqual(mock_request.call_args.kwargs['data'],
                         '{"a": 1, "pw": "NewPass1!"}')


class PreGeneratedRotationTests(TestCase):
    """Service-level pre-generation behavior."""

    def test_pre_generated_reuse_rejection_happens_before_apply(self):
        """A previously-used candidate is rejected before rotate() runs."""
        entry = make_entry(rotation_plugin='ssh',
                           rotation_config={'host': 'h', 'username': 'u'})
        VaultRotationEvent.objects.create(
            entry=entry, reason=VaultRotationEvent.Reason.MANUAL,
            previous_value_hash=hash_previous_value('candidate'),
        )
        with patch('vault.rotation.SSHPasswordRotationPlugin.generate_value',
                   return_value='candidate') as mock_gen, \
             patch('vault.rotation.SSHPasswordRotationPlugin.rotate') as mock_rotate:
            ok, err = rotate_entry(entry, VaultRotationEvent.Reason.MANUAL)
        self.assertFalse(ok)
        self.assertEqual(err, 'That value was previously used for this entry.')
        mock_rotate.assert_not_called()
        self.assertEqual(entry.rotation_events.count(), 1)

    def test_pre_generated_identical_to_current_rejected_before_apply(self):
        """A candidate identical to the current value is rejected pre-apply."""
        entry = make_entry(rotation_plugin='ssh',
                           rotation_config={'host': 'h', 'username': 'u'},
                           encrypted_value='initial-value')
        with patch('vault.rotation.SSHPasswordRotationPlugin.generate_value',
                   return_value='initial-value'), \
             patch('vault.rotation.SSHPasswordRotationPlugin.rotate') as mock_rotate:
            ok, err = rotate_entry(entry, VaultRotationEvent.Reason.MANUAL)
        self.assertFalse(ok)
        self.assertEqual(err, 'The new value is identical to the current value.')
        mock_rotate.assert_not_called()

    @patch('vault.rotation.SSHPasswordRotationPlugin.cleanup', return_value=(True, None))
    def test_pre_generated_candidate_passed_to_rotate_and_stored(self, mock_cleanup):
        """rotate receives (entry, old, candidate) and stores the result."""
        entry = make_entry(rotation_plugin='ssh',
                           rotation_config={'host': 'h', 'username': 'u'})
        with patch('vault.rotation.SSHPasswordRotationPlugin.generate_value',
                   return_value='candidate') as mock_gen, \
             patch('vault.rotation.SSHPasswordRotationPlugin.rotate') as mock_rotate:
            mock_rotate.return_value = RotationResult(new_value='candidate')
            ok, err = rotate_entry(entry, VaultRotationEvent.Reason.MANUAL)
        self.assertTrue(ok)
        mock_rotate.assert_called_once()
        self.assertEqual(mock_rotate.call_args.args[2], 'candidate')
        entry.refresh_from_db()
        self.assertEqual(entry.get_secret_value(), 'candidate')
        self.assertTrue(entry.rotation_events.get().synced_to_system)

    def test_pre_generated_mismatched_result_records_failure(self):
        """A plugin returning a non-candidate value records a failure."""
        entry = make_entry(rotation_plugin='ssh',
                           rotation_config={'host': 'h', 'username': 'u'})
        with patch('vault.rotation.SSHPasswordRotationPlugin.generate_value',
                   return_value='candidate'), \
             patch('vault.rotation.SSHPasswordRotationPlugin.rotate') as mock_rotate:
            mock_rotate.return_value = RotationResult(new_value='other')
            ok, err = rotate_entry(entry, VaultRotationEvent.Reason.MANUAL)
        self.assertFalse(ok)
        self.assertIn('reconcile manually', err)
        entry.refresh_from_db()
        self.assertEqual(entry.get_secret_value(), 'initial-value')
        self.assertFalse(entry.rotation_events.get().synced_to_system)

    def test_legacy_plugin_receives_candidate_none(self):
        """Non-pre-generated plugins get candidate=None (pins the contract)."""
        entry = make_entry(rotation_plugin='aws_iam',
                           rotation_config={'iam_user_name': 'svc-user'})
        with patch('vault.rotation.AWSIAMKeyRotationPlugin.rotate') as mock_rotate:
            mock_rotate.return_value = RotationResult(new_value='{"a": 1}')
            rotate_entry(entry, VaultRotationEvent.Reason.MANUAL)
        self.assertIsNone(mock_rotate.call_args.args[2])

    def test_plugin_choices_includes_all_plugins(self):
        """The registry exposes all seven plugins (blank first)."""
        choices = plugin_choices()
        self.assertEqual(choices[0], ('', 'Vault-only (random value)'))
        names = [name for name, _ in choices]
        for expected in ('aws_iam', 'entra_app_secret', 'ssh', 'postgresql',
                         'mysql', 'winrm', 'http'):
            self.assertIn(expected, names)

    def test_form_requires_config_keys_for_new_plugins(self):
        """The table-driven form validation covers the new plugins (structured fields)."""
        from .forms import VaultEntryForm
        base = {'name': 'X', 'secret_type': 'PASSWORD', 'value': 'v',
                    'max_checkout_minutes': '60'}
        for plugin, first_missing_key in (
            ('ssh', 'host'), ('postgresql', 'host'), ('mysql', 'host'),
            ('winrm', 'host'), ('http', 'url'),
        ):
            form = VaultEntryForm(data={**base, 'rotation_plugin': plugin})
            self.assertFalse(form.is_valid(), plugin)
            self.assertIn(first_missing_key, form.errors)


class RotationValueExcludeTests(TestCase):
    """Crypto exclude param."""

    def test_generate_rotation_value_exclude_removes_chars_and_raises_on_class_loss(self):
        """Excluded chars never appear; excluding a class raises."""
        for _ in range(50):
            value = generate_rotation_value(exclude="'\"")
            self.assertNotIn("'", value)
            self.assertNotIn('"', value)
        with self.assertRaises(ValueError):
            generate_rotation_value(exclude=string.digits)
