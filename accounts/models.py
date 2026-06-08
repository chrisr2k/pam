import logging
import os

from django.contrib.auth.models import AbstractUser
from django.core.signing import Signer, BadSignature
from django.db import models

logger = logging.getLogger(__name__)


class User(AbstractUser):
    """Custom user model linked to Entra ID identity."""

    class Role(models.TextChoices):
        REQUESTER = 'REQUESTER', 'Requester'
        APPROVER = 'APPROVER', 'Approver'
        ADMIN = 'ADMIN', 'Admin'
        AUDITOR = 'AUDITOR', 'Auditor'

    entra_object_id = models.CharField(
        max_length=128, unique=True, null=True, blank=True,
        help_text='Entra ID (Azure AD) object ID',
    )
    role = models.CharField(
        max_length=20, choices=Role.choices, default=Role.REQUESTER,
        help_text='Role within the PAM application',
    )
    manager = models.ForeignKey(
        'self', on_delete=models.SET_NULL, null=True, blank=True,
        related_name='direct_reports',
        help_text='Manager for approval routing',
    )

    def __str__(self):
        return f'{self.get_full_name() or self.username} ({self.get_role_display()})'

    @property
    def is_approver(self):
        return self.role in (self.Role.APPROVER, self.Role.ADMIN)

    @property
    def is_admin_user(self):
        return self.role == self.Role.ADMIN

    @property
    def is_auditor(self):
        return self.role == self.Role.AUDITOR


class EntraConfig(models.Model):
    """Stores Entra ID configuration in the database.

    The client_secret is encrypted at rest using Django's SECRET_KEY
    so it cannot be viewed on the GUI or in the database directly.

    Supports SEPARATE credentials for OIDC login and PIM role management:
    - OIDC app: Used for user login (needs only User.Read)
    - PIM app: Used for role management (needs RoleManagement.ReadWrite.Directory)
      Can use ManagedIdentity, certificate, or client secret
    """

    _signer = Signer(salt='accounts.EntraConfig.client_secret')
    _pim_signer = Signer(salt='accounts.EntraConfig.pim_client_secret')

    # ── OIDC Login App (user authentication) ──────────────────────────────
    tenant_id = models.CharField(
        max_length=128, blank=True, default='',
        verbose_name='Tenant ID (Directory ID)',
        help_text='Your Entra ID tenant ID (GUID from Azure portal)',
    )
    client_id = models.CharField(
        max_length=128, blank=True, default='',
        verbose_name='OIDC Client ID (Application ID)',
        help_text='The Application (client) ID from your OIDC login App Registration',
    )
    client_secret = models.CharField(
        max_length=512, blank=True, default='',
        verbose_name='OIDC Client Secret',
        help_text='The client secret for the OIDC login app (encrypted at rest)',
    )
    redirect_uri = models.CharField(
        max_length=256, blank=True, default='',
        verbose_name='Redirect URI',
        help_text='The redirect URI registered in the OIDC app (e.g. http://localhost:8080/accounts/callback/)',
    )

    # ── PIM Management App (role provisioning) ────────────────────────────
    pim_tenant_id = models.CharField(
        max_length=128, blank=True, default='',
        verbose_name='PIM Tenant ID (optional)',
        help_text='Leave blank to use the same tenant as OIDC. Set if PIM app is in a different tenant.',
    )
    pim_client_id = models.CharField(
        max_length=128, blank=True, default='',
        verbose_name='PIM Client ID (optional)',
        help_text='Separate App Registration for PIM role management. Leave blank to reuse OIDC app.',
    )
    pim_client_secret = models.CharField(
        max_length=512, blank=True, default='',
        verbose_name='PIM Client Secret (optional)',
        help_text='Client secret for the PIM management app (encrypted at rest). '
                  'For production, use a certificate instead.',
    )
    pim_auth_method = models.CharField(
        max_length=32, blank=True, default='',
        verbose_name='PIM Auth Method',
        help_text='Auto-detected: managed_identity, certificate, or client_secret',
        editable=False,
    )

    configured_at = models.DateTimeField(auto_now=True)
    configured_by = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True,
        verbose_name='Configured by',
    )

    class Meta:
        verbose_name = 'Entra ID Configuration'
        verbose_name_plural = 'Entra ID Configuration'

    def __str__(self):
        return f'Entra Config: {self.tenant_id or "Not configured"}'

    def is_configured(self) -> bool:
        """Check if OIDC login is configured."""
        return bool(self.tenant_id and self.client_id and self.get_client_secret())

    def is_pim_configured(self) -> bool:
        """Check if PIM management has separate credentials."""
        if self.pim_client_id and self.get_pim_client_secret():
            return True
        # Fall back to OIDC app credentials
        return self.is_configured()

    # ── OIDC Secret Management ────────────────────────────────────────────

    def get_client_secret(self) -> str:
        """Decrypt and return the OIDC client secret."""
        raw = self.client_secret
        if not raw:
            return ''
        if ':' in raw:
            try:
                return self._signer.unsign(raw)
            except BadSignature:
                logger.warning('Failed to decrypt OIDC client_secret - returning raw value')
                return raw
        return raw

    def set_client_secret(self, value: str) -> None:
        """Encrypt and store the OIDC client secret."""
        if not value:
            self.client_secret = ''
        else:
            self.client_secret = self._signer.sign(value)

    # ── PIM Secret Management ─────────────────────────────────────────────

    def get_pim_client_secret(self) -> str:
        """Decrypt and return the PIM client secret."""
        raw = self.pim_client_secret
        if not raw:
            return ''
        if ':' in raw:
            try:
                return self._pim_signer.unsign(raw)
            except BadSignature:
                logger.warning('Failed to decrypt PIM client_secret - returning raw value')
                return raw
        return raw

    def set_pim_client_secret(self, value: str) -> None:
        """Encrypt and store the PIM client secret."""
        if not value:
            self.pim_client_secret = ''
        else:
            self.pim_client_secret = self._pim_signer.sign(value)

    def save(self, *args, **kwargs):
        # Encrypt secrets before saving if not already encrypted
        raw = self.client_secret
        if raw and ':' not in raw:
            self.client_secret = self._signer.sign(raw)
        raw_pim = self.pim_client_secret
        if raw_pim and ':' not in raw_pim:
            self.pim_client_secret = self._pim_signer.sign(raw_pim)
        # Ensure only one config row exists
        self.pk = 1
        super().save(*args, **kwargs)

    @classmethod
    def get_config(cls):
        config, _ = cls.objects.get_or_create(pk=1)
        return config


class AWSConfig(models.Model):
    """Stores AWS Identity Center configuration in the database.

    Supports multiple authentication methods (no long-lived secrets needed):
      1. IAM Instance Profile (best for EC2/ECS)
      2. IAM Roles Anywhere (best for on-prem/OCI)
      3. AssumeRole (STS - role chaining)
      4. IAM User access keys (dev only - fallback)

    The auth method is auto-detected at runtime.
    """

    # ── SSO Instance ───────────────────────────────────────────────────────
    sso_instance_arn = models.CharField(
        max_length=256, blank=True, default='',
        verbose_name='SSO Instance ARN',
        help_text='AWS IAM Identity Center instance ARN. '
                  'Leave blank to auto-discover if you have only one instance.',
    )
    region = models.CharField(
        max_length=64, blank=True, default='us-east-1',
        verbose_name='AWS Region',
        help_text='AWS region where Identity Center is configured',
    )

    # ── AssumeRole (STS) - Best for cross-account / role chaining ──────────
    role_arn = models.CharField(
        max_length=256, blank=True, default='',
        verbose_name='IAM Role ARN to Assume',
        help_text='ARN of an IAM role with SSO Admin permissions. '
                  'PAM will call STS AssumeRole to get temporary credentials. '
                  'The role must trust PAM\'s current identity (instance profile, '
                  'Roles Anywhere session, or IAM user).',
    )
    role_session_name = models.CharField(
        max_length=128, blank=True, default='PAM-Session',
        verbose_name='STS Role Session Name',
        help_text='Session name for STS AssumeRole (appears in CloudTrail)',
    )
    external_id = models.CharField(
        max_length=256, blank=True, default='',
        verbose_name='STS External ID (optional)',
        help_text='Required if the trust policy has an sts:ExternalId condition',
    )

    # ── IAM Roles Anywhere - Best for on-prem / OCI / non-AWS ──────────────
    roles_anywhere_profile_arn = models.CharField(
        max_length=256, blank=True, default='',
        verbose_name='Roles Anywhere Profile ARN',
        help_text='ARN of the IAM Roles Anywhere trust profile. '
                  'Requires a certificate + private key configured via .env: '
                  'AWS_ROLES_ANYWHERE_CERT_PATH and AWS_ROLES_ANYWHERE_KEY_PATH',
    )
    roles_anywhere_trust_arn = models.CharField(
        max_length=256, blank=True, default='',
        verbose_name='Roles Anywhere Trust Anchor ARN',
        help_text='ARN of the IAM Roles Anywhere trust anchor',
    )

    # ── IAM User Access Keys (dev only - fallback) ─────────────────────────
    access_key_id = models.CharField(
        max_length=128, blank=True, default='',
        verbose_name='IAM Access Key ID (dev only)',
        help_text='Long-lived IAM user access key. Only use for development.',
    )
    secret_access_key = models.CharField(
        max_length=256, blank=True, default='',
        verbose_name='IAM Secret Access Key (dev only)',
        help_text='Long-lived IAM user secret key. Only use for development.',
    )

    # ── Metadata ───────────────────────────────────────────────────────────
    configured_at = models.DateTimeField(auto_now=True)
    configured_by = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True,
        verbose_name='Configured by',
    )

    class Meta:
        verbose_name = 'AWS Identity Center Configuration'
        verbose_name_plural = 'AWS Identity Center Configuration'

    def __str__(self):
        return f'AWS Config: {self.sso_instance_arn or self.region or "Not configured"}'

    def is_configured(self) -> bool:
        """Check if any auth method is configured."""
        return bool(
            self.sso_instance_arn
            or self.role_arn
            or self.roles_anywhere_profile_arn
            or self.access_key_id
        )

    def get_auth_method(self) -> str:
        """Auto-detect which auth method is configured.

        Detection order:
          1. IAM Roles Anywhere (profile ARN or cert files in env)
          2. STS AssumeRole (role_arn is set)
          3. IAM User keys (access_key_id is set)
          4. IAM Instance Profile (default when running on AWS)
        """
        # Check for Roles Anywhere: either profile ARN in DB or cert files in env
        cert_path = os.getenv('AWS_ROLES_ANYWHERE_CERT_PATH', '')
        key_path = os.getenv('AWS_ROLES_ANYWHERE_KEY_PATH', '')
        if self.roles_anywhere_profile_arn or (
            cert_path and key_path and os.path.exists(cert_path) and os.path.exists(key_path)
        ):
            return 'roles_anywhere'
        if self.role_arn:
            return 'assume_role'
        if self.access_key_id:
            return 'iam_user'
        # Instance profile is the default when running on AWS
        return 'instance_profile'

    @classmethod
    def get_config(cls):
        config, _ = cls.objects.get_or_create(pk=1)
        return config


