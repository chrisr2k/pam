"""Review views: campaign list/detail/create plus entry decisions."""

from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin, UserPassesTestMixin
from django.core.exceptions import PermissionDenied
from django.db import transaction
from django.shortcuts import get_object_or_404, redirect
from django.utils import timezone
from django.views import View
from django.views.generic import CreateView, DetailView, ListView

from audit.middleware import log_action
from audit.models import AuditLog
from .forms import ReviewCreateForm
from .models import AccessReview, ReviewEntry
from .stats import latest_grant_anchors, unused_entitlements


class ReviewListView(LoginRequiredMixin, ListView):
    """List access reviews."""
    model = AccessReview
    template_name = 'pam/review_list.html'
    context_object_name = 'reviews'

    def get_queryset(self):
        user = self.request.user
        if user.is_admin_user:
            return AccessReview.objects.all()
        return AccessReview.objects.filter(reviewers=user)


class ReviewDetailView(LoginRequiredMixin, DetailView):
    """View details of an access review."""
    model = AccessReview
    template_name = 'pam/review_detail.html'
    context_object_name = 'review'

    def get_queryset(self):
        # Same visibility rule as the list view: admins see everything,
        # everyone else only campaigns they are assigned to.
        user = self.request.user
        if user.is_admin_user:
            return AccessReview.objects.all()
        return AccessReview.objects.filter(reviewers=user)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        review = self.object
        entries_qs = review.entries.select_related(
            'access_request__requester', 'access_request__role',
            'reviewed_by').order_by('pk')
        context['entries'] = entries_qs

        # Usage stats per distinct (requester, role) pair, attached to entries
        # (Django templates cannot index dicts with variables).
        from .stats import user_role_stats
        usage_by_pair = {}
        for pair in entries_qs.values(
                'access_request__requester_id', 'access_request__role_id').distinct():
            key = (pair['access_request__requester_id'],
                   pair['access_request__role_id'])
            usage_by_pair[key] = user_role_stats(
                pair['access_request__requester_id'],
                pair['access_request__role_id'],
                days=90,
            )
        for entry in entries_qs:
            entry.usage = usage_by_pair.get(
                (entry.access_request.requester_id, entry.access_request.role_id), {})
        context['progress'] = {
            'decided': review.entries.exclude(decision=ReviewEntry.Decision.PENDING).count(),
            'total': review.entries.count(),
        }
        user = self.request.user
        context['can_decide'] = (
            review.status in (AccessReview.Status.DRAFT, AccessReview.Status.IN_PROGRESS)
            and (user.is_admin_user or review.reviewers.filter(pk=user.pk).exists())
        )
        return context


class ReviewCreateView(LoginRequiredMixin, UserPassesTestMixin, CreateView):
    """Staff/admin: create a recertification campaign from grant history."""

    model = AccessReview
    form_class = ReviewCreateForm
    template_name = 'pam/review_form.html'

    def test_func(self):
        return self.request.user.is_staff or self.request.user.is_admin_user

    def form_valid(self, form):
        review = form.save(commit=False)
        review.created_by = self.request.user
        review.save()  # pk needed before building entries

        unused_days = form.cleaned_data.get('unused_days')
        with transaction.atomic():
            from access_requests.models import AccessRequest
            from .stats import GRANT_STATUSES
            if unused_days:
                anchors = unused_entitlements(days=unused_days)
            else:
                grants = AccessRequest.objects.filter(
                    status__in=GRANT_STATUSES, is_break_glass=False)
                anchors = latest_grant_anchors(grants)
            for anchor in anchors:
                ReviewEntry.objects.get_or_create(
                    review=review, access_request=anchor,
                    defaults={'decision': ReviewEntry.Decision.PENDING})

        entry_count = review.entries.count()
        review.status = (AccessReview.Status.IN_PROGRESS
                         if entry_count else AccessReview.Status.DRAFT)
        review.save()
        log_action(
            actor=self.request.user,
            action=AuditLog.Action.REVIEW_CREATED,
            target_type='AccessReview',
            target_id=review.pk,
            details={
                'name': review.name,
                'entry_count': entry_count,
                'unused_days': unused_days or None,
            },
            request=self.request,
        )
        if entry_count:
            messages.success(
                self.request,
                f'Review "{review.name}" created with {entry_count} entries.')
        else:
            messages.warning(
                self.request,
                'No matching grants found — review created as a draft with no entries.')
        return redirect('reviews:detail', pk=review.pk)


class ReviewDecisionView(LoginRequiredMixin, View):
    """POST: decide a single review entry (approve = keep, revoke = remove)."""

    def get(self, request, pk, entry_pk):
        return redirect('reviews:detail', pk=pk)

    def post(self, request, pk, entry_pk):
        review = get_object_or_404(AccessReview, pk=pk)
        if not (request.user.is_admin_user
                or review.reviewers.filter(pk=request.user.pk).exists()):
            raise PermissionDenied('You are not assigned to this review.')

        if review.status not in (AccessReview.Status.DRAFT, AccessReview.Status.IN_PROGRESS):
            messages.error(request, 'This review is already closed.')
            return redirect('reviews:detail', pk=review.pk)

        entry = get_object_or_404(ReviewEntry, pk=entry_pk, review=review)
        decision = request.POST.get('decision', '')
        if decision not in (ReviewEntry.Decision.APPROVED, ReviewEntry.Decision.REVOKED):
            messages.error(request, 'Invalid decision.')
            return redirect('reviews:detail', pk=review.pk)

        entry.decision = decision
        entry.reviewed_by = request.user
        entry.comment = request.POST.get('comment', '')
        entry.reviewed_at = timezone.now()
        entry.save()
        log_action(
            actor=request.user,
            action=AuditLog.Action.REVIEW_ENTRY_DECIDED,
            target_type='ReviewEntry',
            target_id=entry.pk,
            details={
                'role': entry.access_request.role.name,
                'requester': entry.access_request.requester.username,
                'decision': decision,
            },
            request=request,
        )

        if not review.entries.filter(decision=ReviewEntry.Decision.PENDING).exists():
            review.status = AccessReview.Status.COMPLETED
            review.completed_at = timezone.now()
            review.save()
            log_action(
                actor=request.user,
                action=AuditLog.Action.REVIEW_COMPLETED,
                target_type='AccessReview',
                target_id=review.pk,
                details={'name': review.name, 'entries': review.entries.count()},
                request=request,
            )
            messages.success(request, f'Review "{review.name}" completed.')
        else:
            messages.success(request, 'Decision recorded.')
        return redirect('reviews:detail', pk=review.pk)
