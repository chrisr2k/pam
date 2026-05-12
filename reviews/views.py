from django.contrib.auth.mixins import LoginRequiredMixin
from django.views.generic import ListView, DetailView
from .models import AccessReview


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
