"""Tests for the reviews app - models and views."""

from datetime import timedelta

from django.test import TestCase
from django.contrib.auth import get_user_model
from django.urls import reverse
from django.utils import timezone

from .models import AccessReview, ReviewEntry
from roles.models import PrivilegedRole
from access_requests.models import AccessRequest

User = get_user_model()


class AccessReviewModelTests(TestCase):
    """Test the AccessReview model."""

    def setUp(self):
        self.creator = User.objects.create_user(
            username='creator', password='testpass',
        )
        self.reviewer = User.objects.create_user(
            username='reviewer', password='testpass',
        )
        self.review = AccessReview.objects.create(
            name='Q1 Access Review',
            created_by=self.creator,
            due_date=timezone.now() + timedelta(days=14),
        )
        self.review.reviewers.add(self.reviewer)

    def test_review_creation(self):
        """Test basic review creation."""
        self.assertEqual(self.review.name, 'Q1 Access Review')
        self.assertEqual(self.review.created_by, self.creator)
        self.assertIn(self.reviewer, self.review.reviewers.all())
        self.assertEqual(self.review.status, AccessReview.Status.DRAFT)

    def test_review_str(self):
        """Test string representation."""
        self.assertIn('Q1 Access Review', str(self.review))

    def test_default_status_draft(self):
        """Test default status is DRAFT."""
        self.assertEqual(self.review.status, 'DRAFT')

    def test_auto_timestamps(self):
        """Test that created_at is set."""
        self.assertIsNotNone(self.review.created_at)

    def test_entries_relationship(self):
        """Test the entries reverse relationship."""
        role = PrivilegedRole.objects.create(
            name='Test-Role',
            provider='AWS',
            aws_permission_set_arn='ps-123',
        )
        user = User.objects.create_user(username='target', password='testpass')
        access_request = AccessRequest.objects.create(
            requester=user,
            role=role,
            justification='Test',
        )
        entry = ReviewEntry.objects.create(
            review=self.review,
            access_request=access_request,
            decision=ReviewEntry.Decision.APPROVED,
            comment='Still needs access',
        )
        self.assertEqual(self.review.entries.count(), 1)
        self.assertEqual(entry.review, self.review)


class ReviewEntryModelTests(TestCase):
    """Test the ReviewEntry model."""

    def setUp(self):
        self.creator = User.objects.create_user(
            username='creator', password='testpass',
        )
        self.review = AccessReview.objects.create(
            name='Test Review',
            created_by=self.creator,
            due_date=timezone.now() + timedelta(days=7),
        )
        self.role = PrivilegedRole.objects.create(
            name='Test-Role',
            provider='AWS',
            aws_permission_set_arn='ps-123',
        )
        self.target_user = User.objects.create_user(
            username='target', password='testpass',
        )
        self.access_request = AccessRequest.objects.create(
            requester=self.target_user,
            role=self.role,
            justification='Test',
        )
        self.entry = ReviewEntry.objects.create(
            review=self.review,
            access_request=self.access_request,
        )

    def test_entry_creation(self):
        """Test basic entry creation."""
        self.assertEqual(self.entry.review, self.review)
        self.assertEqual(self.entry.access_request, self.access_request)
        self.assertEqual(self.entry.decision, ReviewEntry.Decision.PENDING)

    def test_entry_str(self):
        """Test string representation."""
        self.assertIn(str(self.review.id), str(self.entry))
        self.assertIn(str(self.access_request.id), str(self.entry))

    def test_unique_entry(self):
        """Test that a review can only have one entry per access request."""
        with self.assertRaises(Exception):
            ReviewEntry.objects.create(
                review=self.review,
                access_request=self.access_request,
            )


class ReviewListViewTests(TestCase):
    """Test the review list view."""

    def setUp(self):
        self.list_url = reverse('reviews:list')
        self.admin = User.objects.create_superuser(
            username='admin', password='adminpass',
        )
        self.user = User.objects.create_user(username='user', password='testpass')

    def test_list_requires_login(self):
        """Test that list requires authentication."""
        response = self.client.get(self.list_url)
        self.assertEqual(response.status_code, 302)

    def test_list_loads_for_user(self):
        """Test that list loads for any authenticated user."""
        self.client.force_login(self.user)
        response = self.client.get(self.list_url)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'pam/review_list.html')

    def test_list_loads_for_admin(self):
        """Test that list loads for admin."""
        self.client.force_login(self.admin)
        response = self.client.get(self.list_url)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'pam/review_list.html')


class ReviewDetailViewTests(TestCase):
    """Test the review detail view."""

    def setUp(self):
        self.admin = User.objects.create_superuser(
            username='admin', password='adminpass',
        )
        self.review = AccessReview.objects.create(
            name='Test Review',
            created_by=self.admin,
            due_date=timezone.now() + timedelta(days=7),
        )
        self.review.reviewers.add(self.admin)
        self.detail_url = reverse('reviews:detail', kwargs={'pk': self.review.pk})

    def test_detail_requires_login(self):
        """Test that detail requires authentication."""
        response = self.client.get(self.detail_url)
        self.assertEqual(response.status_code, 302)

    def test_detail_loads_for_admin(self):
        """Test that detail loads for admin."""
        self.client.force_login(self.admin)
        response = self.client.get(self.detail_url)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'pam/review_detail.html')
