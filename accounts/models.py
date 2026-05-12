from django.contrib.auth.models import AbstractUser
from django.db import models


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
    """Stores Entra ID configuration in the database."""

    tenant_id = models.CharField(
        max_length=128, blank=True, default='',
        verbose_name='Tenant ID (Directory ID)',
        help_text='Your Entra ID tenant ID (GUID from Azure portal)',
    )
    client_id = models.CharField(
        max_length=128, blank=True, default='',
        verbose_name='Client ID (Application ID)',
        help_text='The Application (client) ID from your App Registration',
    )
    client_secret = models.CharField(
        max_length=512, blank=True, default='',
        verbose_name='Client Secret',
        help_text='The client secret value from Certificates & Secrets',
    )
    redirect_uri = models.CharField(
        max_length=256, blank=True, default='',
        verbose_name='Redirect URI',
        help_text='The redirect URI registered in the app (e.g. http://localhost:8080/accounts/callback/)',
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
        return bool(self.tenant_id and self.client_id and self.client_secret)

    def save(self, *args, **kwargs):
        # Ensure only one config row exists
        self.pk = 1
        super().save(*args, **kwargs)

    @classmethod
    def get_config(cls):
        config, _ = cls.objects.get_or_create(pk=1)
        return config
