from django.db import models
from django.conf import settings
from django.utils import timezone
from roles.models import PrivilegedRole


class AccessRequest(models.Model):
    """A request for privileged access elevation."""

    class Status(models.TextChoices):
        PENDING = 'PENDING', 'Pending Approval'
        APPROVED = 'APPROVED', 'Approved'
        DENIED = 'DENIED', 'Denied'
        PROVISIONING = 'PROVISIONING', 'Provisioning'
        PROVISIONED = 'PROVISIONED', 'Provisioned'
        ACTIVE = 'ACTIVE', 'Active'
        EXPIRED = 'EXPIRED', 'Expired'
        REVOKED = 'REVOKED', 'Revoked'
        FAILED = 'FAILED', 'Failed'

    requester = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='access_requests',
    )
    role = models.ForeignKey(
        PrivilegedRole,
        on_delete=models.CASCADE,
        related_name='access_requests',
    )
    status = models.CharField(
        max_length=20, choices=Status.choices, default=Status.PENDING,
    )
    justification = models.TextField(
        help_text='Reason for requesting privileged access',
    )
    requested_duration_minutes = models.PositiveIntegerField(
        default=60,
        help_text='Requested duration in minutes',
    )

    # Approval tracking
    approved_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True, blank=True,
        related_name='approved_requests',
    )
    approved_at = models.DateTimeField(null=True, blank=True)
    denial_reason = models.TextField(blank=True)

    # Provisioning tracking
    provisioned_at = models.DateTimeField(null=True, blank=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    deprovisioned_at = models.DateTimeField(null=True, blank=True)

    # Provider reference (e.g., AWS account assignment ID)
    provider_reference_id = models.CharField(
        max_length=2048, blank=True,
        help_text='Provider-specific reference ID (e.g., AWS assignment ID)',
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['status']),
            models.Index(fields=['requester', 'status']),
            models.Index(fields=['expires_at']),
        ]

    def __str__(self):
        return f'{self.requester.username} → {self.role.name} [{self.status}]'

    def approve(self, approver):
        """Approve this request."""
        self.status = self.Status.APPROVED
        self.approved_by = approver
        self.approved_at = timezone.now()
        self.save()

    def deny(self, approver, reason=''):
        """Deny this request."""
        self.status = self.Status.DENIED
        self.approved_by = approver
        self.approved_at = timezone.now()
        self.denial_reason = reason
        self.save()

    def mark_provisioned(self, provider_ref=''):
        """Mark as provisioned."""
        self.status = self.Status.PROVISIONED
        self.provisioned_at = timezone.now()
        self.expires_at = timezone.now() + timezone.timedelta(minutes=self.requested_duration_minutes)
        if provider_ref:
            self.provider_reference_id = provider_ref
        self.save()

    def mark_active(self):
        """Mark as active (user has assumed the role)."""
        self.status = self.Status.ACTIVE
        self.save()

    def mark_expired(self):
        """Mark as expired."""
        self.status = self.Status.EXPIRED
        self.deprovisioned_at = timezone.now()
        self.save()

    def mark_failed(self):
        """Mark as failed."""
        self.status = self.Status.FAILED
        self.save()


class Approval(models.Model):
    """Individual approval record (supports multi-level approval)."""

    class Decision(models.TextChoices):
        APPROVED = 'APPROVED', 'Approved'
        DENIED = 'DENIED', 'Denied'

    request = models.ForeignKey(
        AccessRequest,
        on_delete=models.CASCADE,
        related_name='approvals',
    )
    approver = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='approval_decisions',
    )
    decision = models.CharField(max_length=10, choices=Decision.choices)
    comment = models.TextField(blank=True)
    decided_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['decided_at']
        unique_together = [('request', 'approver')]

    def __str__(self):
        return f'{self.approver.username} {self.decision} request #{self.request.id}'
