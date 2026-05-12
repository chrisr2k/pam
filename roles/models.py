from django.db import models
from django.conf import settings


class PrivilegedRole(models.Model):
    """Catalog of available privileged roles/permission sets."""

    class Provider(models.TextChoices):
        AWS = 'AWS', 'AWS Identity Center'
        ENTRA = 'ENTRA', 'Entra ID PIM'

    name = models.CharField(max_length=255, help_text='Display name of the role')
    description = models.TextField(blank=True, help_text='Description of what this role provides')
    provider = models.CharField(max_length=10, choices=Provider.choices)

    # AWS-specific fields
    aws_permission_set_arn = models.CharField(
        max_length=2048, blank=True,
        help_text='AWS SSO Permission Set ARN',
    )
    aws_account_id = models.CharField(
        max_length=64, blank=True,
        help_text='AWS account ID (leave blank for all accounts)',
    )
    aws_account_name = models.CharField(
        max_length=255, blank=True,
        help_text='AWS account display name',
    )

    # Entra-specific fields
    entra_role_id = models.CharField(
        max_length=128, blank=True,
        help_text='Entra ID role definition ID',
    )
    entra_role_name = models.CharField(
        max_length=255, blank=True,
        help_text='Entra ID role display name',
    )

    # Policy
    max_duration_minutes = models.PositiveIntegerField(
        default=480,  # 8 hours
        help_text='Maximum allowed duration in minutes',
    )
    requires_approval = models.BooleanField(
        default=True,
        help_text='Whether this role requires approval to activate',
    )
    is_active = models.BooleanField(
        default=True,
        help_text='Whether this role is available for requests',
    )
    approvers = models.ManyToManyField(
        settings.AUTH_USER_MODEL,
        blank=True,
        related_name='approvable_roles',
        help_text='Users who can approve requests for this role',
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['provider', 'name']
        constraints = [
            models.UniqueConstraint(
                fields=['provider', 'aws_permission_set_arn', 'aws_account_id'],
                name='unique_aws_role',
                condition=models.Q(provider='AWS'),
            ),
            models.UniqueConstraint(
                fields=['provider', 'entra_role_id'],
                name='unique_entra_role',
                condition=models.Q(provider='ENTRA'),
            ),
        ]

    def clean(self):
        from django.core.exceptions import ValidationError
        if self.provider == self.Provider.AWS:
            if not self.aws_permission_set_arn:
                raise ValidationError({'aws_permission_set_arn': 'Permission Set ARN is required for AWS roles.'})
            # Check uniqueness manually for AWS roles
            qs = PrivilegedRole.objects.filter(
                provider='AWS',
                aws_permission_set_arn=self.aws_permission_set_arn,
                aws_account_id=self.aws_account_id,
            )
            if self.pk:
                qs = qs.exclude(pk=self.pk)
            if qs.exists():
                raise ValidationError(
                    f'AWS role with Permission Set ARN "{self.aws_permission_set_arn}" '
                    f'and Account ID "{self.aws_account_id}" already exists.'
                )
        elif self.provider == self.Provider.ENTRA:
            if not self.entra_role_id:
                raise ValidationError({'entra_role_id': 'Entra ID Role ID is required for Entra roles.'})
            # Check uniqueness manually for Entra roles
            qs = PrivilegedRole.objects.filter(
                provider='ENTRA',
                entra_role_id=self.entra_role_id,
            )
            if self.pk:
                qs = qs.exclude(pk=self.pk)
            if qs.exists():
                raise ValidationError(
                    f'Entra role with Role ID "{self.entra_role_id}" already exists.'
                )

    def save(self, *args, **kwargs):
        self.clean()
        super().save(*args, **kwargs)

    def __str__(self):
        if self.provider == self.Provider.AWS:
            account = f' [{self.aws_account_name or self.aws_account_id}]' if self.aws_account_id else ''
            return f'AWS: {self.name}{account}'
        return f'Entra: {self.name}'
