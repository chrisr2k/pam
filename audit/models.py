from django.db import models
from django.conf import settings
from django.core.signing import Signer, BadSignature


class AuditLog(models.Model):
    """Immutable audit log for all PAM actions."""

    class Action(models.TextChoices):
        LOGIN = 'LOGIN', 'User Login'
        LOGOUT = 'LOGOUT', 'User Logout'
        REQUEST_CREATED = 'REQUEST_CREATED', 'Access Request Created'
        REQUEST_APPROVED = 'REQUEST_APPROVED', 'Access Request Approved'
        APPROVAL_RECORDED = 'APPROVAL_RECORDED', 'Approval Vote Recorded'
        REQUEST_DENIED = 'REQUEST_DENIED', 'Access Request Denied'
        PROVISIONING_STARTED = 'PROVISIONING_STARTED', 'Provisioning Started'
        PROVISIONING_SUCCEEDED = 'PROVISIONING_SUCCEEDED', 'Provisioning Succeeded'
        PROVISIONING_FAILED = 'PROVISIONING_FAILED', 'Provisioning Failed'
        ACCESS_EXPIRED = 'ACCESS_EXPIRED', 'Access Expired'
        ACCESS_REVOKED = 'ACCESS_REVOKED', 'Access Revoked'
        ADMIN_REVOKED = 'ADMIN_REVOKED', 'Access Revoked by Admin'
        MFA_ENROLLED = 'MFA_ENROLLED', 'MFA Enrolled'
        MFA_REMOVED = 'MFA_REMOVED', 'MFA Removed'
        MFA_CHALLENGE_FAILED = 'MFA_CHALLENGE_FAILED', 'MFA Challenge Failed'
        BREAK_GLASS_TRIGGERED = 'BREAK_GLASS_TRIGGERED', 'Break Glass Triggered'
        ROLE_CREATED = 'ROLE_CREATED', 'Privileged Role Created'
        ROLE_UPDATED = 'ROLE_UPDATED', 'Privileged Role Updated'
        REVIEW_CREATED = 'REVIEW_CREATED', 'Access Review Created'
        REVIEW_COMPLETED = 'REVIEW_COMPLETED', 'Access Review Completed'
        REVIEW_ENTRY_DECIDED = 'REVIEW_ENTRY_DECIDED', 'Review Entry Decided'
        SCIM_USER_PROVISIONED = 'SCIM_USER_PROVISIONED', 'SCIM User Provisioned'
        SCIM_USER_UPDATED = 'SCIM_USER_UPDATED', 'SCIM User Updated'
        SCIM_USER_DEPROVISIONED = 'SCIM_USER_DEPROVISIONED', 'SCIM User Deprovisioned'
        VAULT_ENTRY_CREATED = 'VAULT_ENTRY_CREATED', 'Vault Entry Created'
        VAULT_ENTRY_UPDATED = 'VAULT_ENTRY_UPDATED', 'Vault Entry Updated'
        VAULT_ENTRY_DELETED = 'VAULT_ENTRY_DELETED', 'Vault Entry Deleted'
        VAULT_SECRET_REVEALED = 'VAULT_SECRET_REVEALED', 'Vault Secret Revealed'
        VAULT_SECRET_ROTATED = 'VAULT_SECRET_ROTATED', 'Vault Secret Rotated'
        ALERT_RAISED = 'ALERT_RAISED', 'Threat Alert Raised'

    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True, blank=True,
        related_name='audit_actions',
    )
    action = models.CharField(max_length=50, choices=Action.choices)
    target_type = models.CharField(
        max_length=50, blank=True,
        help_text='Type of object affected (e.g., AccessRequest, PrivilegedRole)',
    )
    target_id = models.CharField(
        max_length=128, blank=True,
        help_text='ID of the affected object',
    )
    details = models.JSONField(default=dict, blank=True)
    ip_address = models.GenericIPAddressField(blank=True, null=True)
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['action']),
            models.Index(fields=['actor']),
            models.Index(fields=['timestamp']),
            models.Index(fields=['target_type', 'target_id']),
        ]

    def __str__(self):
        return f'{self.get_action_display()} by {self.actor} at {self.timestamp}'


class SIEMConfig(models.Model):
    """Singleton configuration for SIEM export via HTTPS webhook.

    The forwarder (audit/tasks.py) drains AuditLog rows above `watermark` in
    id order and POSTs them to the webhook. Delivery is at-least-once: on a
    failure the watermark is not advanced and the batch is retried on the
    next tick. The api_token is encrypted at rest with the same Signer
    pattern as EntraConfig secrets.
    """

    class PayloadMode(models.TextChoices):
        SPLUNK_HEC = 'splunk_hec', 'Splunk HEC'
        SENTINEL = 'sentinel', 'Microsoft Sentinel'
        GENERIC = 'generic', 'Generic JSON webhook'

    _signer = Signer(salt='audit.SIEMConfig.api_token')

    enabled = models.BooleanField(default=False, verbose_name='Enable SIEM Export')
    webhook_url = models.CharField(
        max_length=512, blank=True, default='',
        verbose_name='Webhook URL',
        help_text='Splunk HEC endpoint, Sentinel Data Collection Endpoint, or generic webhook URL',
    )
    payload_mode = models.CharField(
        max_length=20, choices=PayloadMode.choices, default=PayloadMode.SPLUNK_HEC,
        verbose_name='Payload Mode',
    )
    api_token = models.CharField(
        max_length=512, blank=True, default='',
        verbose_name='API Token',
        help_text='Bearer/HEC token (encrypted at rest)',
    )
    token_header = models.CharField(
        max_length=64, default='Authorization',
        verbose_name='Auth Header Name',
    )
    token_prefix = models.CharField(
        max_length=64, default='Splunk ',
        verbose_name='Auth Header Prefix',
        help_text="Prefix for the auth header value (e.g. 'Splunk ', 'Bearer '). Blank sends the token bare.",
    )
    action_filter = models.CharField(
        max_length=512, blank=True, default='',
        verbose_name='Action Filter',
        help_text='Comma-separated action names; blank forwards all actions',
    )

    # Forwarder state
    watermark = models.BigIntegerField(
        default=0,
        verbose_name='Watermark',
        help_text='Highest AuditLog id successfully forwarded',
    )
    last_error = models.TextField(blank=True, default='', verbose_name='Last Error')
    last_error_at = models.DateTimeField(null=True, blank=True, verbose_name='Last Error At')
    last_run_at = models.DateTimeField(null=True, blank=True, verbose_name='Last Run At')
    last_success_at = models.DateTimeField(null=True, blank=True, verbose_name='Last Success At')

    configured_at = models.DateTimeField(auto_now=True)
    configured_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL,
        null=True, blank=True, verbose_name='Configured by',
    )

    class Meta:
        verbose_name = 'SIEM Configuration'
        verbose_name_plural = 'SIEM Configuration'

    def __str__(self):
        if self.enabled and self.webhook_url:
            return f'SIEM: {self.get_payload_mode_display()} (enabled)'
        return 'SIEM: Not configured'

    def save(self, *args, **kwargs):
        # Encrypt the API token before saving if not already encrypted
        raw = self.api_token
        if raw and ':' not in raw:
            self.api_token = self._signer.sign(raw)
        self.pk = 1  # Singleton
        super().save(*args, **kwargs)

    @classmethod
    def get_config(cls):
        config, _ = cls.objects.get_or_create(pk=1)
        return config

    def get_api_token(self) -> str:
        """Decrypt and return the API token."""
        raw = self.api_token
        if not raw:
            return ''
        if ':' in raw:
            try:
                return self._signer.unsign(raw)
            except BadSignature:
                return raw
        return raw

    def set_api_token(self, value: str) -> None:
        """Encrypt and store the API token."""
        if not value:
            self.api_token = ''
        else:
            self.api_token = self._signer.sign(value)

    def get_effective_token(self) -> str:
        """DB token, falling back to the SIEM_API_TOKEN env/vault secret."""
        from django.conf import settings
        return self.get_api_token() or getattr(settings, 'SIEM_API_TOKEN', '')
