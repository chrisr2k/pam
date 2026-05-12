from django.db import models
from django.conf import settings


class AuditLog(models.Model):
    """Immutable audit log for all PAM actions."""

    class Action(models.TextChoices):
        LOGIN = 'LOGIN', 'User Login'
        LOGOUT = 'LOGOUT', 'User Logout'
        REQUEST_CREATED = 'REQUEST_CREATED', 'Access Request Created'
        REQUEST_APPROVED = 'REQUEST_APPROVED', 'Access Request Approved'
        REQUEST_DENIED = 'REQUEST_DENIED', 'Access Request Denied'
        PROVISIONING_STARTED = 'PROVISIONING_STARTED', 'Provisioning Started'
        PROVISIONING_SUCCEEDED = 'PROVISIONING_SUCCEEDED', 'Provisioning Succeeded'
        PROVISIONING_FAILED = 'PROVISIONING_FAILED', 'Provisioning Failed'
        ACCESS_EXPIRED = 'ACCESS_EXPIRED', 'Access Expired'
        ACCESS_REVOKED = 'ACCESS_REVOKED', 'Access Revoked'
        ROLE_CREATED = 'ROLE_CREATED', 'Privileged Role Created'
        ROLE_UPDATED = 'ROLE_UPDATED', 'Privileged Role Updated'
        REVIEW_CREATED = 'REVIEW_CREATED', 'Access Review Created'
        REVIEW_COMPLETED = 'REVIEW_COMPLETED', 'Access Review Completed'

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
