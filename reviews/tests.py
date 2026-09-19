"""Tests for the reviews app - models and views."""

from datetime import timedelta

from django.test import TestCase
from django.contrib.auth import get_user_model
from django.urls import reverse
from django.utils import timezone

from .models import AccessReview, ReviewEntry
from roles.models import PrivilegedRole
from access_requests.models import AccessRequest
from audit.models import AuditLog

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


class RoleMiningStatsTests(TestCase):
    """Stats helpers and unused-entitlement mining."""

    def setUp(self):
        self.user = User.objects.create_user(username='u1', password='x')
        self.role = PrivilegedRole.objects.create(
            name='Stats-Role', provider='AWS', aws_permission_set_arn='ps-1')
        self.now = timezone.now()

    def _grant(self, status, requester=None, created=None, expires=None, break_glass=False):
        # created_at is auto_now_add (insert-only) — force it via update()
        grant = AccessRequest.objects.create(
            requester=requester or self.user, role=self.role, justification='t',
            status=status, provisioned_at=created or self.now,
            expires_at=expires, is_break_glass=break_glass)
        if created is not None:
            AccessRequest.objects.filter(pk=grant.pk).update(created_at=created)
            grant.created_at = created
        return grant

    def test_counts_only_grant_statuses(self):
        self._grant('PROVISIONED')
        self._grant('DENIED')
        self._grant('PENDING')
        from .stats import role_usage_stats
        stats = role_usage_stats(self.role, days=90)
        self.assertEqual(stats['request_count'], 1)

    def test_window_filters_request_count(self):
        old = self.now - timedelta(days=120)
        self._grant('EXPIRED', created=old)
        self._grant('PROVISIONED', created=self.now)
        from .stats import role_usage_stats
        stats = role_usage_stats(self.role, days=90)
        self.assertEqual(stats['request_count'], 1)

    def test_distinct_users_counted_once(self):
        self._grant('EXPIRED')
        self._grant('EXPIRED')
        from .stats import role_usage_stats
        stats = role_usage_stats(self.role, days=90)
        self.assertEqual(stats['distinct_users'], 1)

    def test_last_request_at_ignores_window(self):
        old = self.now - timedelta(days=120)
        self._grant('EXPIRED', created=old)
        from .stats import role_usage_stats
        stats = role_usage_stats(self.role, days=90)
        self.assertEqual(stats['last_request_at'], old)

    def test_active_now_counts_only_currently_provisioned(self):
        self._grant('PROVISIONED', expires=self.now + timedelta(hours=1))
        self._grant('PROVISIONED', expires=self.now - timedelta(hours=1))
        from .stats import role_usage_stats
        stats = role_usage_stats(self.role, days=90)
        self.assertEqual(stats['active_now'], 1)

    def test_user_role_stats_scoped(self):
        self._grant('EXPIRED')
        other = User.objects.create_user(username='u2', password='x')
        self._grant('EXPIRED', requester=other)
        from .stats import user_role_stats
        stats = user_role_stats(self.user, self.role, days=90)
        self.assertEqual(stats['request_count'], 1)
        self.assertFalse(stats['active_now'])

    def test_unused_entitlements_returns_pairs_older_than_cutoff(self):
        self._grant('EXPIRED', created=self.now - timedelta(days=120))
        from .stats import unused_entitlements
        anchors = unused_entitlements(days=90)
        self.assertEqual(len(anchors), 1)

    def test_unused_entitlements_excludes_recent_grants(self):
        self._grant('EXPIRED', created=self.now - timedelta(days=5))
        from .stats import unused_entitlements
        self.assertEqual(unused_entitlements(days=90), [])

    def test_unused_entitlements_excludes_active_grants(self):
        self._grant('PROVISIONED', created=self.now - timedelta(days=120),
                    expires=self.now + timedelta(hours=2))
        from .stats import unused_entitlements
        self.assertEqual(unused_entitlements(days=90), [])

    def test_unused_entitlements_excludes_break_glass(self):
        self._grant('EXPIRED', created=self.now - timedelta(days=120), break_glass=True)
        from .stats import unused_entitlements
        self.assertEqual(unused_entitlements(days=90), [])

    def test_unused_entitlements_denied_only_never_appears(self):
        self._grant('DENIED', created=self.now - timedelta(days=120))
        from .stats import unused_entitlements
        self.assertEqual(unused_entitlements(days=90), [])

    def test_unused_entitlements_single_latest_anchor(self):
        self._grant('EXPIRED', created=self.now - timedelta(days=120))
        self._grant('EXPIRED', created=self.now - timedelta(days=150))
        from .stats import unused_entitlements
        anchors = unused_entitlements(days=90)
        self.assertEqual(len(anchors), 1)
        self.assertEqual(anchors[0].created_at, self.now - timedelta(days=120))


class ReviewCreateViewTests(TestCase):
    """Campaign creation with role-mining filters."""

    def setUp(self):
        self.staff = User.objects.create_user(
            username='staff', password='x', is_staff=True, role='ADMIN')
        self.user = User.objects.create_user(username='u1', password='x')
        self.role = PrivilegedRole.objects.create(
            name='Mine-Role', provider='AWS', aws_permission_set_arn='ps-2')
        self.now = timezone.now()

    def _grant(self, created=None, break_glass=False):
        # created_at is auto_now_add (insert-only) — force it via update()
        grant = AccessRequest.objects.create(
            requester=self.user, role=self.role, justification='t',
            status='EXPIRED', provisioned_at=created or self.now,
            expires_at=self.now - timedelta(hours=1), is_break_glass=break_glass)
        if created is not None:
            AccessRequest.objects.filter(pk=grant.pk).update(created_at=created)
            grant.created_at = created
        return grant

    def _post(self, unused_days=''):
        return self.client.post(reverse('reviews:create'), {
            'name': 'Mining Review',
            'due_date': (self.now + timedelta(days=7)).strftime('%Y-%m-%dT%H:%M'),
            'unused_days': unused_days,
        })

    def test_non_staff_forbidden(self):
        self.client.force_login(self.user)
        response = self.client.get(reverse('reviews:create'))
        self.assertEqual(response.status_code, 403)

    def test_creates_review_with_entries(self):
        self._grant()
        self.client.force_login(self.staff)
        response = self._post()
        review = AccessReview.objects.get(name='Mining Review')
        self.assertRedirects(response, reverse('reviews:detail', kwargs={'pk': review.pk}))
        self.assertEqual(review.status, AccessReview.Status.IN_PROGRESS)
        self.assertEqual(review.created_by, self.staff)
        self.assertEqual(review.entries.count(), 1)
        self.assertTrue(AuditLog.objects.filter(action='REVIEW_CREATED').exists())

    def test_unused_days_filters_entries(self):
        self._grant(created=self.now - timedelta(days=5))
        self._grant(created=self.now - timedelta(days=120))
        self.client.force_login(self.staff)
        self._post(unused_days='90')
        review = AccessReview.objects.get(name='Mining Review')
        # Both grants share one (user, role) pair; the latest is 5 days old
        # so the pair is NOT unused → zero entries.
        self.assertEqual(review.entries.count(), 0)
        self.assertEqual(review.status, AccessReview.Status.DRAFT)

    def test_zero_matches_creates_draft(self):
        self.client.force_login(self.staff)
        self._post()
        review = AccessReview.objects.get(name='Mining Review')
        self.assertEqual(review.status, AccessReview.Status.DRAFT)
        self.assertEqual(review.entries.count(), 0)

    def test_break_glass_grants_excluded(self):
        self._grant(break_glass=True)
        self.client.force_login(self.staff)
        self._post()
        review = AccessReview.objects.get(name='Mining Review')
        self.assertEqual(review.entries.count(), 0)


class ReviewDecisionViewTests(TestCase):
    """Entry decisions and completion semantics."""

    def setUp(self):
        self.admin = User.objects.create_user(
            username='admin', password='x', role='ADMIN', is_staff=True)
        self.reviewer = User.objects.create_user(username='rv', password='x')
        self.other = User.objects.create_user(username='other', password='x')
        self.role = PrivilegedRole.objects.create(
            name='Decide-Role', provider='AWS', aws_permission_set_arn='ps-3')
        self.target = User.objects.create_user(username='target', password='x')
        self.grant = AccessRequest.objects.create(
            requester=self.target, role=self.role, justification='t',
            status='EXPIRED')
        self.review = AccessReview.objects.create(
            name='Decide Review', created_by=self.admin,
            due_date=timezone.now() + timedelta(days=7),
            status=AccessReview.Status.IN_PROGRESS)
        self.review.reviewers.add(self.reviewer)
        self.entry = ReviewEntry.objects.create(
            review=self.review, access_request=self.grant)

    def _decide(self, user, decision='APPROVED'):
        self.client.force_login(user)
        return self.client.post(
            reverse('reviews:decide', kwargs={'pk': self.review.pk, 'entry_pk': self.entry.pk}),
            {'decision': decision, 'comment': 'ok'})

    def test_non_reviewer_forbidden(self):
        self.client.force_login(self.other)
        response = self.client.post(
            reverse('reviews:decide', kwargs={'pk': self.review.pk, 'entry_pk': self.entry.pk}),
            {'decision': 'APPROVED'})
        self.assertEqual(response.status_code, 403)

    def test_admin_can_decide_without_being_listed(self):
        response = self._decide(self.admin)
        self.assertRedirects(response, reverse('reviews:detail', kwargs={'pk': self.review.pk}))
        self.entry.refresh_from_db()
        self.assertEqual(self.entry.decision, ReviewEntry.Decision.APPROVED)
        self.assertEqual(self.entry.reviewed_by, self.admin)
        self.assertTrue(AuditLog.objects.filter(action='REVIEW_ENTRY_DECIDED').exists())

    def test_reviewer_decides_entry(self):
        response = self._decide(self.reviewer, decision='REVOKED')
        self.entry.refresh_from_db()
        self.assertEqual(self.entry.decision, ReviewEntry.Decision.REVOKED)
        self.assertEqual(self.entry.reviewed_by, self.reviewer)
        self.assertEqual(self.entry.comment, 'ok')
        self.assertIsNotNone(self.entry.reviewed_at)

    def test_last_decision_completes_review(self):
        self._decide(self.reviewer)
        self.review.refresh_from_db()
        self.assertEqual(self.review.status, AccessReview.Status.COMPLETED)
        self.assertIsNotNone(self.review.completed_at)
        self.assertTrue(AuditLog.objects.filter(action='REVIEW_COMPLETED').exists())

    def test_completed_review_rejects_decisions(self):
        self._decide(self.reviewer)
        self.entry.decision = ReviewEntry.Decision.PENDING
        self.entry.save()
        response = self._decide(self.reviewer)
        self.entry.refresh_from_db()
        self.assertEqual(self.entry.decision, ReviewEntry.Decision.PENDING)

    def test_detail_restricted_to_reviewers(self):
        self.client.force_login(self.other)
        response = self.client.get(
            reverse('reviews:detail', kwargs={'pk': self.review.pk}))
        self.assertEqual(response.status_code, 404)

    def test_detail_shows_usage_context(self):
        self.client.force_login(self.reviewer)
        response = self.client.get(
            reverse('reviews:detail', kwargs={'pk': self.review.pk}))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Usage (90d)')
        self.assertContains(response, '0 of 1 decided')
