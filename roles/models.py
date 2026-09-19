from django.db import models
from django.conf import settings


class PrivilegedRole(models.Model):
    """Catalog of available privileged roles/permission sets."""

    class Provider(models.TextChoices):
        AWS = 'AWS', 'AWS Identity Center'
        ENTRA = 'ENTRA', 'Entra ID PIM'
        VAULT = 'VAULT', 'PAM Vault'

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

    # Vault-specific field
    vault_entry = models.OneToOneField(
        'vault.VaultEntry', on_delete=models.SET_NULL,
        null=True, blank=True, related_name='shim_role',
        help_text='Vault entry backing this role (VAULT provider only)',
    )

    # ABAC (Attribute-Based Access Control) via Entra ID directory attributes
    abac_enabled = models.BooleanField(
        default=False,
        help_text='Use ABAC via Entra directory attributes instead of direct account assignments',
    )
    entra_attribute_name = models.CharField(
        max_length=128, blank=True, default='',
        help_text='Entra ID extension attribute name (e.g. extension_<appId>_awsAdminAccounts)',
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
    is_break_glass = models.BooleanField(
        default=False,
        help_text='Eligible for break-glass emergency access (enforced by BreakGlassView)',
    )
    is_active = models.BooleanField(
        default=True,
        help_text='Whether this role is available for requests',
    )

    class ApprovalPolicy(models.TextChoices):
        ANY_ONE = 'ANY_ONE', 'Any one approver'
        ALL = 'ALL', 'All approvers'
        QUORUM = 'QUORUM', 'Fixed quorum'

    approval_policy = models.CharField(
        max_length=10, choices=ApprovalPolicy.choices,
        default=ApprovalPolicy.ANY_ONE,
        help_text='Votes required to approve: any single approver, every current approver, or a fixed quorum count.',
    )
    quorum_count = models.PositiveIntegerField(
        default=1,
        help_text='Distinct approver votes required when policy is QUORUM. '
                  'If the role has fewer approvers than this count, all approvers must vote.',
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

    def approval_threshold(self) -> int:
        """Number of distinct approver votes needed to approve a request.

        Computed dynamically at vote time: ALL uses the current approver
        count, QUORUM is capped at the approver count so a request can never
        become permanently unapprovable.
        """
        approver_count = self.approvers.count()
        if self.approval_policy == self.ApprovalPolicy.ALL:
            return approver_count
        if self.approval_policy == self.ApprovalPolicy.QUORUM:
            return min(self.quorum_count, approver_count)
        return 1  # ANY_ONE

    def clean(self):
        from django.core.exceptions import ValidationError
        if self.quorum_count < 1:
            raise ValidationError({'quorum_count': 'Quorum count must be at least 1.'})
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
        elif self.provider == self.Provider.VAULT:
            if not self.vault_entry_id:
                raise ValidationError({'vault_entry': 'A vault entry is required for Vault roles.'})

    def save(self, *args, **kwargs):
        self.clean()
        super().save(*args, **kwargs)

    def __str__(self):
        if self.provider == self.Provider.AWS:
            account = f' [{self.aws_account_name or self.aws_account_id}]' if self.aws_account_id else ''
            return f'AWS: {self.name}{account}'
        if self.provider == self.Provider.ENTRA:
            return f'Entra: {self.name}'
        return f'Vault: {self.name}'
