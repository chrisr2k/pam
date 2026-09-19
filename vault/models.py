"""Vault models: encrypted secret entries and their rotation history."""

from django.conf import settings
from django.db import models

from .crypto import decrypt_value, encrypt_value


class VaultEntry(models.Model):
    """A single encrypted secret (password, SSH key, or API token).

    Checkout rides the AccessRequest JIT flow: a shim PrivilegedRole
    (provider=VAULT) is created/updated by signals on save, so requesters
    check out through the normal request → approval → expiry machinery.
    """

    class SecretType(models.TextChoices):
        PASSWORD = 'PASSWORD', 'Password'
        SSH_KEY = 'SSH_KEY', 'SSH Private Key'
        API_TOKEN = 'API_TOKEN', 'API Token'

    name = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    secret_type = models.CharField(
        max_length=20, choices=SecretType.choices, default=SecretType.PASSWORD,
    )
    encrypted_value = models.TextField(
        help_text='Fernet-encrypted secret value',
    )
    auto_rotate = models.BooleanField(
        default=False,
        help_text='Generate a new random value automatically when a checkout ends',
    )
    requires_approval = models.BooleanField(
        default=True,
        help_text='Whether checkout requires approval (mirrored to the shim role)',
    )
    max_checkout_minutes = models.PositiveIntegerField(
        default=60,
        help_text='Maximum checkout duration in minutes (mirrored to the shim role)',
    )
    is_active = models.BooleanField(
        default=True,
        help_text='Whether this entry is available for checkout',
    )

    rotation_plugin = models.CharField(
        max_length=32, blank=True, default='',
        help_text='Rotation plugin: blank = vault-only random value. '
                  'Plugins: aws_iam (AWS IAM access key), entra_app_secret (Entra app client secret).',
    )
    rotation_config = models.JSONField(
        default=dict, blank=True,
        help_text='Plugin connection settings (JSON, never secrets). '
                  'AWS: {"iam_user_name": "...", "region": "us-east-1"}. '
                  'Entra: {"tenant_id": "...", "client_id": "..."}.',
    )
    rotation_state = models.JSONField(
        default=dict, blank=True, editable=False,
        help_text='Plugin bookkeeping (e.g. Entra password credential keyId). Managed by rotation code.',
    )

    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL,
        null=True, blank=True, related_name='vault_entries_created',
    )
    updated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL,
        null=True, blank=True, related_name='vault_entries_updated',
    )
    last_rotated_at = models.DateTimeField(null=True, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['name']

    def __str__(self):
        return self.name

    @property
    def rotation_plugin_label(self) -> str:
        from .rotation import get_plugin
        plugin = get_plugin(self.rotation_plugin) if self.rotation_plugin else None
        return plugin.label if plugin else 'Vault-only (random value)'

    def set_secret_value(self, plaintext: str) -> None:
        """Encrypt and store a plaintext secret value."""
        self.encrypted_value = encrypt_value(plaintext)

    def get_secret_value(self) -> str:
        """Decrypt and return the stored secret value."""
        return decrypt_value(self.encrypted_value)

    def save(self, *args, **kwargs):
        # Auto-encrypt plaintext values (Fernet tokens always start gAAAA)
        if self.encrypted_value and not self.encrypted_value.startswith('gAAAA'):
            self.encrypted_value = encrypt_value(self.encrypted_value)
        super().save(*args, **kwargs)


class VaultRotationEvent(models.Model):
    """History of secret rotations, with keyed hashes for reuse detection."""

    class Reason(models.TextChoices):
        MANUAL = 'MANUAL', 'Manual rotation'
        AUTO_CHECKIN = 'AUTO_CHECKIN', 'Auto-rotation on checkin'

    entry = models.ForeignKey(
        VaultEntry, on_delete=models.CASCADE, related_name='rotation_events',
    )
    reason = models.CharField(max_length=20, choices=Reason.choices)
    rotated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL,
        null=True, blank=True, related_name='vault_rotations',
        help_text='Null for system (checkin) rotations',
    )
    previous_value_hash = models.CharField(
        max_length=64,
        help_text='Keyed hash of the previous value (for reuse detection)',
    )
    plugin = models.CharField(
        max_length=32, blank=True, default='',
        help_text='Rotation plugin used (blank = vault-only random value)',
    )
    synced_to_system = models.BooleanField(
        default=False,
        help_text='Whether the new value was pushed to the real target system',
    )
    error = models.TextField(
        blank=True, default='',
        help_text='Rotation/cleanup failure text (never contains the secret)',
    )
    rotated_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-rotated_at']

    def __str__(self):
        return f'{self.entry.name} rotated ({self.get_reason_display()}) at {self.rotated_at}'
