from django.db import models
from django.conf import settings
from django.utils import timezone


class AccessReview(models.Model):
    """A scheduled access review campaign."""

    class Status(models.TextChoices):
        DRAFT = 'DRAFT', 'Draft'
        IN_PROGRESS = 'IN_PROGRESS', 'In Progress'
        COMPLETED = 'COMPLETED', 'Completed'
        CANCELLED = 'CANCELLED', 'Cancelled'

    name = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.DRAFT)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='created_reviews',
    )
    reviewers = models.ManyToManyField(
        settings.AUTH_USER_MODEL,
        blank=True,
        related_name='assigned_reviews',
        help_text='Users assigned to review access',
    )
    due_date = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f'{self.name} ({self.get_status_display()})'


class ReviewEntry(models.Model):
    """Individual access entry to be reviewed."""

    class Decision(models.TextChoices):
        APPROVED = 'APPROVED', 'Approved - Keep Access'
        REVOKED = 'REVOKED', 'Revoked - Remove Access'
        PENDING = 'PENDING', 'Pending Review'

    review = models.ForeignKey(
        AccessReview,
        on_delete=models.CASCADE,
        related_name='entries',
    )
    access_request = models.ForeignKey(
        'access_requests.AccessRequest',
        on_delete=models.CASCADE,
        related_name='review_entries',
    )
    decision = models.CharField(
        max_length=10, choices=Decision.choices, default=Decision.PENDING,
    )
    reviewed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True, blank=True,
    )
    comment = models.TextField(blank=True)
    reviewed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        unique_together = [('review', 'access_request')]

    def __str__(self):
        return f'Review {self.review.id} - Request #{self.access_request.id}'
