"""Credential rotation plugins: vault-only random values or real-system sync.

CPM-style rotation: the plugin creates and verifies the new credential on the
target system, the vault stores it, and only then is the old credential
revoked (cleanup). A failure at any point keeps the existing vault value, so
the vault never drifts from a target system that still uses the old
credential.
"""

import json
import logging
import re
from dataclasses import dataclass, field
from datetime import timedelta

import boto3
import httpx
import msal
import paramiko
import psycopg2
import psycopg2.sql
import pymysql
import requests
import winrm
from botocore.exceptions import BotoCoreError, ClientError
from cryptography.fernet import InvalidToken
from django.db import transaction
from django.utils import timezone

from audit.middleware import log_action
from .crypto import generate_rotation_value, hash_previous_value
from .models import VaultEntry, VaultRotationEvent

logger = logging.getLogger(__name__)

MAX_ERROR_LENGTH = 200


@dataclass
class RotationResult:
    new_value: str | None = None
    error: str | None = None
    # Merged into entry.rotation_state AFTER a successful store
    state: dict = field(default_factory=dict)
    # Opaque payload passed to cleanup()
    cleanup_context: dict = field(default_factory=dict)


class BaseRotationPlugin:
    """Interface for credential rotation plugins."""

    name = ''
    label = ''
    # When True, the plugin's new value is generated (generate_value) and
    # reuse-checked BEFORE rotate() touches the target system — required for
    # password-replacement plugins, where the old value is destroyed in place
    # and a post-apply rejection would strand the vault on a dead credential.
    pre_generated = False

    def generate_value(self) -> str:
        """Generate a candidate value (pure, no I/O)."""
        return generate_rotation_value()

    def _config(self, entry, defaults=None):
        """Merge plugin defaults with entry.rotation_config; validate required keys."""
        cfg = {**(PLUGIN_DEFAULTS.get(self.name) or {}),
               **(defaults or {}),
               **(entry.rotation_config or {})}
        for key in REQUIRED_CONFIG_KEYS.get(self.name, ()):
            if not cfg.get(key):
                return None, f"rotation_config is missing '{key}'"
        return cfg, None

    def rotate(self, entry, old_value: str, candidate: str | None = None) -> RotationResult:
        """Create and verify a new credential on the target system."""
        raise NotImplementedError

    def cleanup(self, entry, old_value: str, new_value: str,
                context: dict | None = None):
        """Revoke the old credential. Runs AFTER the vault stores the new one.

        Returns (ok, error_or_None). A cleanup failure never fails the
        rotation — the old credential is orphaned and recorded.
        """
        return True, None

    def discard(self, new_value: str, state: dict) -> None:
        """Best-effort revoke of a created-but-never-stored credential."""
        return None


# Per-plugin required rotation_config keys (also drives form validation)
REQUIRED_CONFIG_KEYS = {
    'aws_iam': ('iam_user_name',),
    'entra_app_secret': ('tenant_id', 'client_id'),
    'ssh': ('host', 'username'),
    'postgresql': ('host', 'username'),
    'mysql': ('host', 'username'),
    'winrm': ('host', 'username'),
    'http': ('url',),
}

# Per-plugin config defaults (single source for runtime + form help text)
PLUGIN_DEFAULTS = {
    'aws_iam': {'region': 'us-east-1'},
    'ssh': {'port': 22, 'use_sudo': True, 'timeout': 15},
    'postgresql': {'port': 5432, 'dbname': 'postgres', 'connect_timeout': 15},
    'mysql': {'port': 3306, 'host_part': '%', 'connect_timeout': 15},
    'winrm': {'port': 5986, 'use_ssl': True, 'cert_validation': 'ignore',
              'account_type': 'local', 'operation_timeout_sec': 30,
              'read_timeout_sec': 30},
    'http': {'method': 'POST', 'headers': {}, 'body_template': '',
             'success_status': 200, 'timeout': 30,
             'verify_method': 'GET', 'verify_status': 200,
             'cleanup_method': 'POST', 'cleanup_status': 200},
}


def _reuse_error(entry, old_value, new_value):
    """Reuse rejection message, or None if the value is fresh."""
    new_hash = hash_previous_value(new_value)
    if new_hash == hash_previous_value(old_value):
        return 'The new value is identical to the current value.'
    if entry.rotation_events.filter(previous_value_hash=new_hash).exists():
        return 'That value was previously used for this entry.'
    return None


def _truncate_error(text: str) -> str:
    """Keep error strings short and body-free (bodies may echo credentials)."""
    text = str(text or '').strip()
    return text[:MAX_ERROR_LENGTH]


# ── Plugins ──────────────────────────────────────────────────────────────────


class VaultOnlyRotationPlugin(BaseRotationPlugin):
    """Default: generate a random value stored only in the vault."""

    name = 'vault_only'
    label = 'Vault-only (random value)'

    def rotate(self, entry, old_value, candidate=None):
        return RotationResult(new_value=generate_rotation_value())


class AWSIAMKeyRotationPlugin(BaseRotationPlugin):
    """Rotate an IAM user's access key using the entry's current key pair."""

    name = 'aws_iam'
    label = 'AWS IAM access key'

    def _session(self, access_key_id, secret_access_key, region):
        return boto3.Session(
            aws_access_key_id=access_key_id,
            aws_secret_access_key=secret_access_key,
            region_name=region,
        )

    def _parse_key_pair(self, value):
        try:
            pair = json.loads(value)
            return (pair['access_key_id'], pair['secret_access_key'])
        except (json.JSONDecodeError, KeyError, TypeError):
            return None

    def _delete_key(self, access_key_id, secret_access_key, user_name, region):
        try:
            iam = self._session(access_key_id, secret_access_key, region).client('iam')
            iam.delete_access_key(UserName=user_name, AccessKeyId=access_key_id)
            return True, None
        except ClientError as e:
            code = e.response.get('Error', {}).get('Code', '')
            return False, _truncate_error(f'AWS delete_access_key failed ({code}): {e}')
        except BotoCoreError as e:
            return False, _truncate_error(f'AWS delete_access_key failed: {e}')

    def rotate(self, entry, old_value, candidate=None):
        cfg, err = self._config(entry)
        if err:
            return RotationResult(error=err)

        pair = self._parse_key_pair(old_value)
        if pair is None:
            return RotationResult(error=(
                'Entry value is not a valid AWS key pair JSON — re-import it as '
                '{"access_key_id": "...", "secret_access_key": "..."}'))
        old_key_id, old_secret = pair
        user_name = cfg['iam_user_name']
        region = cfg.get('region') or 'us-east-1'

        try:
            iam = self._session(old_key_id, old_secret, region).client('iam')
            resp = iam.create_access_key(UserName=user_name)
            new_key = resp['AccessKey']
        except ClientError as e:
            code = e.response.get('Error', {}).get('Code', '')
            if code == 'LimitExceeded':
                return RotationResult(error=(
                    'IAM user already has two access keys — delete an unused '
                    'key in the AWS console and retry.'))
            return RotationResult(error=_truncate_error(
                f'AWS create_access_key failed ({code}): {e}'))
        except BotoCoreError as e:
            return RotationResult(error=_truncate_error(
                f'AWS create_access_key failed: {e}'))

        new_key_id = new_key['AccessKeyId']
        new_secret = new_key['SecretAccessKey']

        # Verify the new key BEFORE the caller stores it (the old key is
        # deleted right after the store — a bad new key would be catastrophic).
        try:
            sts = self._session(new_key_id, new_secret, region).client('sts')
            identity = sts.get_caller_identity()
            arn = identity.get('Arn', '')
            if not arn.endswith(f':user/{user_name}'):
                raise ValueError(f'unexpected identity ARN: {arn}')
        except Exception as e:
            self._delete_key(new_key_id, new_secret, user_name, region)
            return RotationResult(error=_truncate_error(
                f'New AWS key failed verification (get_caller_identity): {e}'))

        new_value = json.dumps({
            'access_key_id': new_key_id,
            'secret_access_key': new_secret,
        })
        return RotationResult(
            new_value=new_value,
            state={'iam_user_name': user_name, 'region': region},
        )

    def cleanup(self, entry, old_value, new_value, context=None):
        cfg, err = self._config(entry)
        if err:
            return False, err
        pair = self._parse_key_pair(old_value)
        if pair is None:
            return False, 'Old AWS key pair unparseable — remove it manually.'
        return self._delete_key(
            pair[0], pair[1], cfg['iam_user_name'], cfg.get('region') or 'us-east-1')

    def discard(self, new_value, state):
        pair = self._parse_key_pair(new_value)
        if pair is None:
            return
        self._delete_key(
            pair[0], pair[1],
            (state or {}).get('iam_user_name', ''),
            (state or {}).get('region', 'us-east-1'),
        )


class EntraAppSecretRotationPlugin(BaseRotationPlugin):
    """Rotate an Entra app registration's client secret using the app itself.

    Prerequisite: the app registration needs the Application.ReadWrite.OwnedBy
    permission to rotate its own credentials.
    """

    name = 'entra_app_secret'
    label = 'Entra app client secret'
    GRAPH_API_BASE = 'https://graph.microsoft.com/v1.0'
    GRAPH_SCOPE = ['https://graph.microsoft.com/.default']

    def _acquire_token(self, cfg, secret):
        app = msal.ConfidentialClientApplication(
            client_id=cfg['client_id'],
            client_credential=secret,
            authority=f"https://login.microsoftonline.com/{cfg['tenant_id']}",
        )
        result = app.acquire_token_for_client(scopes=self.GRAPH_SCOPE)
        if 'access_token' not in result:
            error = result.get('error_description') or result.get('error') or 'unknown'
            return None, _truncate_error(f'Entra token acquisition failed: {error}')
        return result['access_token'], None

    def _graph_request(self, cfg, secret, method, path, data=None):
        token, err = self._acquire_token(cfg, secret)
        if err:
            return None, err
        url = f'{self.GRAPH_API_BASE}{path}'
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json',
        }
        try:
            response = httpx.request(method, url, headers=headers, json=data, timeout=30)
            if response.status_code >= 400:
                # Never embed response bodies in surfaced errors (may echo
                # credential material); log them instead.
                logger.error(
                    'Graph API error during rotation: %s %s (status %s)',
                    method, path, response.status_code)
                return None, _truncate_error(
                    f'Entra Graph {method} failed (status {response.status_code})')
            return response, None
        except httpx.HTTPError as e:
            return None, _truncate_error(f'Entra Graph request failed: {e}')

    def rotate(self, entry, old_value, candidate=None):
        cfg, err = self._config(entry)
        if err:
            return RotationResult(error=err)
        # Capture the old keyId BEFORE creating anything (Graph never
        # returns secretText again; removePassword needs the keyId).
        old_key_id = (entry.rotation_state or {}).get('entra_key_id')

        path = f"/applications(appId='{cfg['client_id']}')/passwordCredentials"
        body = {
            'passwordCredential': {
                'displayName': f"PAM rotation {timezone.now():%Y-%m-%d %H:%M}",
                'endDateTime': (timezone.now() + timedelta(days=730)).strftime('%Y-%m-%dT%H:%M:%SZ'),
            },
        }
        resp, err = self._graph_request(cfg, old_value, 'POST', path, data=body)
        if err:
            return RotationResult(error=err)
        secret_text = resp.json().get('secretText')
        key_id = resp.json().get('keyId')
        if not secret_text or not key_id:
            return RotationResult(error='Entra addPassword response missing secretText/keyId')

        return RotationResult(
            new_value=secret_text,
            state={'entra_key_id': key_id},
            cleanup_context={'old_key_id': old_key_id},
        )

    def cleanup(self, entry, old_value, new_value, context=None):
        cfg, err = self._config(entry)
        if err:
            return False, err
        context = context or {}
        old_key_id = context.get('old_key_id')

        if not old_key_id:
            # Legacy entry with no recorded keyId: match by hint prefix.
            resp, err = self._graph_request(
                cfg, new_value, 'GET',
                f"/applications(appId='{cfg['client_id']}')/passwordCredentials")
            if err:
                return False, err
            creds = resp.json().get('value', [])
            current_key = (entry.rotation_state or {}).get('entra_key_id')
            candidates = [
                c for c in creds
                if c.get('hint') == old_value[:3] and c.get('keyId') != current_key
            ]
            if len(candidates) != 1:
                return False, (
                    f'Old Entra credential keyId unknown — remove the previous '
                    f'secret manually (hint prefix "{old_value[:3]}").')
            old_key_id = candidates[0]['keyId']

        path = f"/applications(appId='{cfg['client_id']}')/removePassword"
        _, err = self._graph_request(cfg, new_value, 'POST', path,
                                     data={'keyId': old_key_id})
        if err:
            return False, err
        return True, None

    def discard(self, new_value, state):
        # Best-effort: needs entry config for client_id — unavailable here.
        return None


class SSHPasswordRotationPlugin(BaseRotationPlugin):
    """Rotate a Linux/Unix account password over SSH via stdin-based chpasswd.

    Password-replacement plugin: pre_generated, so the candidate is
    reuse-checked BEFORE the target password is changed.
    """

    name = 'ssh'
    label = 'SSH (Linux/Unix)'
    pre_generated = True

    USERNAME_RE = re.compile(r'^[A-Za-z0-9_.-]+$')

    def _config(self, entry):
        cfg, err = super()._config(entry, defaults={
            'port': 22, 'use_sudo': True, 'timeout': 15})
        if err:
            return None, err
        if not self.USERNAME_RE.match(str(cfg['username'])):
            return None, 'ssh username must match [A-Za-z0-9_.-]+'
        return cfg, None

    def _connect(self, cfg, password):
        client = paramiko.SSHClient()
        # TOFU host keys (documented); password is the only auth source
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            hostname=cfg['host'],
            port=int(cfg['port']),
            username=cfg['username'],
            password=password,
            timeout=int(cfg.get('timeout', 15)),
            allow_agent=False,
            look_for_keys=False,
        )
        return client

    def _set_password(self, client, cfg, sudo_password, new_password):
        """Change the password via chpasswd, feeding stdin (never argv)."""
        username = cfg['username']
        if cfg.get('use_sudo'):
            # get_pty covers sudo installs with requiretty; -S reads the
            # sudo password from stdin
            stdin, stdout, _ = client.exec_command('sudo -S chpasswd', get_pty=True)
            stdin.write(f'{sudo_password}\n')
        else:
            stdin, stdout, _ = client.exec_command('chpasswd')
        stdin.write(f'{username}:{new_password}\n')
        stdin.flush()
        stdin.channel.shutdown_write()
        exit_status = stdout.channel.recv_exit_status()
        return exit_status == 0

    def _rollback(self, cfg, old_value, new_value):
        """Best-effort re-apply of the old password."""
        try:
            client = self._connect(cfg, new_value)
            sudo_password = new_value
        except Exception:
            client = self._connect(cfg, old_value)
            sudo_password = old_value
        try:
            return self._set_password(client, cfg, sudo_password, old_value)
        except Exception:
            return False
        finally:
            client.close()

    def rotate(self, entry, old_value, candidate=None):
        cfg, err = self._config(entry)
        if err:
            return RotationResult(error=err)
        new_value = candidate or self.generate_value()

        try:
            client = self._connect(cfg, old_value)
        except paramiko.AuthenticationException:
            return RotationResult(error=(
                f'SSH authentication failed for {cfg["username"]}@'
                f'{cfg["host"]}:{cfg["port"]} — old credential rejected'))
        except Exception as e:
            return RotationResult(error=_truncate_error(f'SSH connection failed: {e}'))

        try:
            applied = self._set_password(client, cfg, old_value, new_value)
        finally:
            client.close()
        if not applied:
            return RotationResult(error=(
                'chpasswd failed — the old password may still be active'))

        # Verify with the new password; roll back if it does not work.
        try:
            verify_client = self._connect(cfg, new_value)
        except Exception:
            rollback_ok = self._rollback(cfg, old_value, new_value)
            msg = 'New SSH password failed verification.'
            if not rollback_ok:
                msg += ' Rollback failed — the target may now use the new password; reconcile manually.'
            return RotationResult(error=msg)
        try:
            stdin, stdout, _ = verify_client.exec_command('whoami')
            who = stdout.read().decode().strip()
        finally:
            verify_client.close()
        if who != cfg['username']:
            rollback_ok = self._rollback(cfg, old_value, new_value)
            msg = 'New SSH password failed verification (unexpected whoami).'
            if not rollback_ok:
                msg += ' Rollback failed — the target may now use the new password; reconcile manually.'
            return RotationResult(error=msg)
        return RotationResult(new_value=new_value)


class PostgreSQLPasswordRotationPlugin(BaseRotationPlugin):
    """Rotate a PostgreSQL role password with the role's current password."""

    name = 'postgresql'
    label = 'PostgreSQL password'
    pre_generated = True

    def _config(self, entry):
        return super()._config(entry, defaults={
            'port': 5432, 'dbname': 'postgres', 'connect_timeout': 15})

    def _connect(self, cfg, password):
        return psycopg2.connect(
            host=cfg['host'], port=int(cfg['port']),
            user=cfg['username'], password=password,
            dbname=cfg['dbname'], connect_timeout=int(cfg.get('connect_timeout', 15)))

    def _alter(self, conn, username, password):
        conn.autocommit = True
        cur = conn.cursor()
        try:
            cur.execute(
                psycopg2.sql.SQL('ALTER USER {} WITH PASSWORD %s')
                .format(psycopg2.sql.Identifier(username)),
                (password,))
        finally:
            cur.close()

    def rotate(self, entry, old_value, candidate=None):
        cfg, err = self._config(entry)
        if err:
            return RotationResult(error=err)
        new_value = candidate or self.generate_value()

        try:
            conn = self._connect(cfg, old_value)
        except psycopg2.OperationalError as e:
            if 'password' in str(e).lower() or 'authentication' in str(e).lower():
                return RotationResult(error=(
                    f'PostgreSQL authentication failed for {cfg["username"]}@'
                    f'{cfg["host"]}:{cfg["port"]} — old credential rejected'))
            return RotationResult(error=_truncate_error(f'PostgreSQL connection failed: {e}'))

        try:
            try:
                self._alter(conn, cfg['username'], new_value)
            except psycopg2.Error as e:
                return RotationResult(error=_truncate_error(
                    f'PostgreSQL ALTER USER failed: {e}'))

            # Verify with the new password; ALTER ROLE does not kill the
            # existing session, so rollback happens on the open connection.
            try:
                verify_conn = self._connect(cfg, new_value)
            except Exception:
                rollback_ok = True
                try:
                    self._alter(conn, cfg['username'], old_value)
                except Exception:
                    rollback_ok = False
                msg = 'New PostgreSQL password failed verification.'
                if not rollback_ok:
                    msg += ' Rollback failed — the target may now use the new password; reconcile manually.'
                return RotationResult(error=msg)
            try:
                cur = verify_conn.cursor()
                cur.execute('SELECT 1')
                cur.fetchone()
                cur.close()
            finally:
                verify_conn.close()
            return RotationResult(new_value=new_value)
        finally:
            conn.close()


class MySQLPasswordRotationPlugin(BaseRotationPlugin):
    """Rotate a MySQL/MariaDB account password (MySQL 8+ / MariaDB 10.2+)."""

    name = 'mysql'
    label = 'MySQL password'
    pre_generated = True

    USERNAME_RE = re.compile(r'^[A-Za-z0-9_.-]+$')
    HOST_PART_RE = re.compile(r'^[A-Za-z0-9_.%-]+$')

    def _config(self, entry):
        cfg, err = super()._config(entry, defaults={
            'port': 3306, 'host_part': '%', 'connect_timeout': 15})
        if err:
            return None, err
        if not self.USERNAME_RE.match(str(cfg['username'])):
            return None, 'mysql username must match [A-Za-z0-9_.-]+'
        if not self.HOST_PART_RE.match(str(cfg['host_part'])):
            return None, 'mysql host_part must match [A-Za-z0-9_.%-]+'
        return cfg, None

    def _connect(self, cfg, password):
        return pymysql.connect(
            host=cfg['host'], port=int(cfg['port']),
            user=cfg['username'], password=password,
            connect_timeout=int(cfg.get('connect_timeout', 15)),
            autocommit=True)

    def _escape_password(self, conn, password):
        with conn.cursor() as cur:
            cur.execute('SELECT @@sql_mode')
            sql_mode = (cur.fetchone() or ('',))[0] or ''
        if 'NO_BACKSLASH_ESCAPES' in sql_mode.upper():
            return password.replace("'", "''")
        escaped = pymysql.converters.escape_string(password)
        if isinstance(escaped, bytes):
            escaped = escaped.decode('utf-8')
        return escaped

    def rotate(self, entry, old_value, candidate=None):
        cfg, err = self._config(entry)
        if err:
            return RotationResult(error=err)
        new_value = candidate or self.generate_value()

        try:
            conn = self._connect(cfg, old_value)
        except pymysql.err.OperationalError as e:
            if getattr(e, 'args', (None,))[0] == 1045:  # access denied
                return RotationResult(error=(
                    f'MySQL authentication failed for {cfg["username"]}@'
                    f'{cfg["host"]}:{cfg["port"]} — old credential rejected'))
            return RotationResult(error=_truncate_error(f'MySQL connection failed: {e}'))

        try:
            escaped = self._escape_password(conn, new_value)
            sql = (f"ALTER USER '{cfg['username']}'@'{cfg['host_part']}' "
                   f"IDENTIFIED BY '{escaped}'")
            try:
                with conn.cursor() as cur:
                    cur.execute(sql)
            except pymysql.err.Error as e:
                return RotationResult(error=_truncate_error(f'MySQL ALTER USER failed: {e}'))

            try:
                verify_conn = self._connect(cfg, new_value)
            except Exception:
                rollback_ok = True
                try:
                    old_escaped = self._escape_password(conn, old_value)
                    rollback_sql = (f"ALTER USER '{cfg['username']}'@'{cfg['host_part']}' "
                                    f"IDENTIFIED BY '{old_escaped}'")
                    with conn.cursor() as cur:
                        cur.execute(rollback_sql)
                except Exception:
                    rollback_ok = False
                msg = 'New MySQL password failed verification.'
                if not rollback_ok:
                    msg += ' Rollback failed — the target may now use the new password; reconcile manually.'
                return RotationResult(error=msg)
            try:
                with verify_conn.cursor() as cur:
                    cur.execute('SELECT 1')
                    cur.fetchone()
            finally:
                verify_conn.close()
            return RotationResult(new_value=new_value)
        finally:
            conn.close()


class WinRMPasswordRotationPlugin(BaseRotationPlugin):
    """Rotate a Windows local or AD account password over WinRM."""

    name = 'winrm'
    label = 'Windows (WinRM)'
    pre_generated = True

    def generate_value(self):
        # Quotes must not appear inside the PowerShell single-quoted literal
        return generate_rotation_value(exclude="'\"")

    def _config(self, entry):
        return super()._config(entry, defaults={
            'port': 5986, 'use_ssl': True, 'cert_validation': 'ignore',
            'account_type': 'local',
            'operation_timeout_sec': 30, 'read_timeout_sec': 30})

    def _session(self, cfg, password):
        scheme = 'https' if cfg.get('use_ssl') else 'http'
        return winrm.Session(
            f'{scheme}://{cfg["host"]}:{cfg["port"]}/wsman',
            auth=(cfg['username'], password),
            transport='basic',
            server_cert_validation=cfg.get('cert_validation', 'ignore'),
            operation_timeout_sec=int(cfg.get('operation_timeout_sec', 30)),
            read_timeout_sec=int(cfg.get('read_timeout_sec', 30)),
        )

    def _script(self, cfg, password):
        username = cfg['username'].split('\\')[-1]
        escaped = password.replace("'", "''")  # defense-in-depth
        if cfg.get('account_type') == 'ad':
            return (f"Set-ADAccountPassword -Identity '{username}' "
                    f"-NewPassword (ConvertTo-SecureString -String '{escaped}' "
                    f"-AsPlainText -Force)")
        return f"net user '{username}' '{escaped}'"

    def _apply(self, session, cfg, password):
        result = session.run_cmd(
            'powershell.exe', ['-NoProfile', '-Command', self._script(cfg, password)])
        return result.status_code == 0

    def rotate(self, entry, old_value, candidate=None):
        cfg, err = self._config(entry)
        if err:
            return RotationResult(error=err)
        new_value = candidate or self.generate_value()

        try:
            session = self._session(cfg, old_value)
            applied = self._apply(session, cfg, new_value)
        except Exception as e:
            return RotationResult(error=_truncate_error(f'WinRM request failed: {e}'))
        if not applied:
            return RotationResult(error=(
                'WinRM password change command failed — the old password '
                'may still be active'))

        try:
            verify_session = self._session(cfg, new_value)
            result = verify_session.run_cmd('powershell.exe',
                                            ['-NoProfile', '-Command', 'whoami'])
            if result.status_code != 0:
                raise ValueError(f'whoami exited {result.status_code}')
        except Exception:
            rollback_ok = True
            try:
                self._apply(self._session(cfg, new_value), cfg, old_value)
            except Exception:
                rollback_ok = False
            msg = 'New Windows password failed verification.'
            if not rollback_ok:
                msg += ' Rollback failed — the target may now use the new password; reconcile manually.'
            return RotationResult(error=msg)
        return RotationResult(new_value=new_value)


class GenericHTTPRotationPlugin(BaseRotationPlugin):
    """Rotate via a generic webhook: POST the new value to a configured URL.

    Success status only proves the endpoint accepted the call; configure
    verify_url where the remote API offers one. No rollback exists for
    webhooks — verify failures say so explicitly.
    """

    name = 'http'
    label = 'Generic HTTP webhook'
    pre_generated = True

    def _config(self, entry):
        return super()._config(entry, defaults={
            'method': 'POST', 'headers': {}, 'body_template': '',
            'success_status': 200, 'timeout': 30,
            'verify_method': 'GET', 'verify_status': 200,
            'cleanup_method': 'POST', 'cleanup_status': 200})

    def _render(self, template, old_value, new_value):
        # Literal replacement, NOT str.format (JSON bodies are full of {})
        return str(template).replace('{old_value}', old_value).replace(
            '{new_value}', new_value)

    def _request(self, cfg, url, method, expected_status, old_value, new_value):
        rendered_url = self._render(url, old_value, new_value)
        headers = {
            k: self._render(v, old_value, new_value)
            for k, v in (cfg.get('headers') or {}).items()}
        body = self._render(cfg.get('body_template', ''), old_value, new_value)
        try:
            resp = requests.request(
                method, rendered_url, headers=headers or None,
                data=body or None, timeout=int(cfg.get('timeout', 30)))
        except requests.RequestException as e:
            return _truncate_error(f'HTTP request failed: {e}')
        expected = (expected_status,) if isinstance(expected_status, int) else tuple(expected_status)
        if resp.status_code not in expected:
            return _truncate_error(f'HTTP request failed (status {resp.status_code})')
        return None

    def rotate(self, entry, old_value, candidate=None):
        cfg, err = self._config(entry)
        if err:
            return RotationResult(error=err)
        new_value = candidate or self.generate_value()

        err = self._request(cfg, cfg['url'], cfg.get('method', 'POST'),
                            cfg.get('success_status', 200), old_value, new_value)
        if err:
            return RotationResult(error=err)
        if cfg.get('verify_url'):
            err = self._request(cfg, cfg['verify_url'], cfg.get('verify_method', 'GET'),
                                cfg.get('verify_status', 200), old_value, new_value)
            if err:
                return RotationResult(error=(
                    f'{err} The target may already have the new value; '
                    f'reconcile manually.'))
        return RotationResult(new_value=new_value)

    def cleanup(self, entry, old_value, new_value, context=None):
        cfg, err = self._config(entry)
        if err or not cfg.get('cleanup_url'):
            return True, None
        err = self._request(cfg, cfg['cleanup_url'], cfg.get('cleanup_method', 'POST'),
                            cfg.get('cleanup_status', 200), old_value, new_value)
        if err:
            return False, err
        return True, None


PLUGINS: dict = {
    'aws_iam': AWSIAMKeyRotationPlugin,
    'entra_app_secret': EntraAppSecretRotationPlugin,
    'ssh': SSHPasswordRotationPlugin,
    'postgresql': PostgreSQLPasswordRotationPlugin,
    'mysql': MySQLPasswordRotationPlugin,
    'winrm': WinRMPasswordRotationPlugin,
    'http': GenericHTTPRotationPlugin,
}


def get_plugin(name: str) -> BaseRotationPlugin:
    return PLUGINS[name]()


def plugin_choices():
    return [('', 'Vault-only (random value)')] + [
        (name, cls.label) for name, cls in PLUGINS.items()]


# ── Rotation service ─────────────────────────────────────────────────────────


def rotate_entry(entry, reason, user=None, explicit_value=None, request=None):
    """Rotate an entry's secret, syncing to the target system when a plugin is set.

    Returns (ok, error_or_None). On failure the existing value is kept; the
    failure is recorded as a VaultRotationEvent with synced_to_system=False.
    """
    with transaction.atomic():
        entry = VaultEntry.objects.select_for_update().get(pk=entry.pk)

        try:
            old_value = entry.get_secret_value()
        except InvalidToken:
            logger.error(f'Failed to decrypt vault entry {entry.pk} ({entry.name})')
            return False, 'Vault entry cannot be decrypted (was SECRET_KEY rotated?).'

        plugin_name = entry.rotation_plugin or 'vault_only'

        if explicit_value is not None and entry.rotation_plugin:
            return False, (
                'Typed values cannot be set on plugin-managed entries — the '
                'vault would not match the target system.')

        plugin = None
        result = None
        if explicit_value is not None:
            new_value = explicit_value
            synced = False
        else:
            try:
                plugin = get_plugin(entry.rotation_plugin) if entry.rotation_plugin else VaultOnlyRotationPlugin()
            except KeyError:
                return _record_rotation_failure(
                    entry, reason, user, plugin_name, old_value,
                    f'Unknown rotation plugin {entry.rotation_plugin!r}', request)
            # Generate-before-apply: password-replacement plugins get their
            # candidate value reuse-checked BEFORE the target is touched, so a
            # rejection can never strand the vault on a dead credential.
            candidate = None
            if plugin.pre_generated:
                candidate = plugin.generate_value()
                reuse_err = _reuse_error(entry, old_value, candidate)
                if reuse_err:
                    return False, reuse_err
            result = plugin.rotate(entry, old_value, candidate)
            if result.error:
                return _record_rotation_failure(
                    entry, reason, user, plugin_name, old_value,
                    _truncate_error(result.error), request)
            if plugin.pre_generated and result.new_value != candidate:
                return _record_rotation_failure(
                    entry, reason, user, plugin_name, old_value,
                    'Plugin returned a value that was not the pre-checked '
                    'candidate — target state unknown; reconcile manually.',
                    request)
            new_value = result.new_value
            synced = plugin.name != 'vault_only'

        # Reuse checks (shared by typed and plugin paths; for pre-generated
        # plugins this is a redundant but harmless re-check of the candidate)
        reuse_err = _reuse_error(entry, old_value, new_value)
        if reuse_err:
            if plugin is not None and result is not None:
                plugin.discard(new_value, result.state)
            return False, reuse_err

        # Store the new value BEFORE the old credential dies
        entry.set_secret_value(new_value)
        entry.last_rotated_at = timezone.now()
        if user is not None:
            entry.updated_by = user
        if result is not None and result.state:
            entry.rotation_state = {**entry.rotation_state, **result.state}
        entry.save()

    # Cleanup after the store: vault value is live before the old credential
    # is revoked. Failures never fail the rotation.
    cleanup_err = None
    if plugin is not None:
        cleanup_ok, cleanup_err = plugin.cleanup(
            entry, old_value, new_value, result.cleanup_context if result else None)
        if not cleanup_ok:
            logger.warning(
                'Rotation cleanup failed for vault entry %s (%s): %s',
                entry.pk, entry.name, cleanup_err)
            cleanup_err = _truncate_error(cleanup_err)

    VaultRotationEvent.objects.create(
        entry=entry,
        reason=reason,
        rotated_by=user,
        previous_value_hash=hash_previous_value(old_value),
        plugin=plugin_name,
        synced_to_system=synced,
        error=cleanup_err or '',
    )
    log_action(
        actor=user,
        action='VAULT_SECRET_ROTATED',
        target_type='VaultEntry',
        target_id=entry.pk,
        details={
            'entry': entry.name,
            'reason': 'manual' if reason == VaultRotationEvent.Reason.MANUAL else 'auto_checkin',
            'plugin': plugin_name,
            'synced': synced,
            **({'cleanup_error': cleanup_err} if cleanup_err else {}),
        },
        request=request,
    )
    logger.info('Rotated vault entry %s (%s) plugin=%s synced=%s',
                entry.pk, entry.name, plugin_name, synced)
    return True, None


def _record_rotation_failure(entry, reason, user, plugin_name, old_value, error, request=None):
    """Record a failed rotation; the existing value is never destroyed."""
    error = _truncate_error(error)
    VaultRotationEvent.objects.create(
        entry=entry,
        reason=reason,
        rotated_by=user,
        previous_value_hash=hash_previous_value(old_value),
        plugin=plugin_name,
        synced_to_system=False,
        error=error,
    )
    log_action(
        actor=user,
        action='VAULT_SECRET_ROTATED',
        target_type='VaultEntry',
        target_id=entry.pk,
        details={
            'entry': entry.name,
            'reason': 'manual' if reason == VaultRotationEvent.Reason.MANUAL else 'auto_checkin',
            'plugin': plugin_name,
            'synced': False,
            'error': error,
        },
        request=request,
    )
    logger.error('Rotation failed for vault entry %s (%s): %s', entry.pk, entry.name, error)
    return False, error
