from urllib.parse import urlencode

from django.contrib.auth.mixins import LoginRequiredMixin
from django.db.models import Q
from django.http import Http404
from django.views.generic import ListView, DetailView
from .models import PrivilegedRole


class RoleListView(LoginRequiredMixin, ListView):
    """List all available privileged roles, with search, filters and pagination.

    GET params:
      q        — free-text search (name, description, AWS account name, Entra role name)
      provider — AWS / ENTRA / VAULT
      approval — yes / no (requires approval vs instant grant)
      page     — page number (24 per page)
    """

    model = PrivilegedRole
    template_name = 'pam/role_list.html'
    context_object_name = 'roles'
    paginate_by = 24

    def get(self, request, *args, **kwargs):
        try:
            return super().get(request, *args, **kwargs)
        except Http404:
            # Out-of-range/garbage page number (e.g. filters tightened while
            # deep in the list) — fall back to the first page.
            params = request.GET.copy()
            params.pop(self.page_kwarg, None)
            request.GET = params
            return super().get(request, *args, **kwargs)

    def get_queryset(self):
        qs = PrivilegedRole.objects.filter(is_active=True)

        self.query = self.request.GET.get('q', '').strip()
        provider = self.request.GET.get('provider', '').strip()
        approval = self.request.GET.get('approval', '').strip()
        # Normalize: unknown values are dropped, not applied
        self.provider_filter = provider if provider in PrivilegedRole.Provider.values else ''
        self.approval_filter = approval if approval in ('yes', 'no') else ''

        if self.query:
            qs = qs.filter(
                Q(name__icontains=self.query)
                | Q(description__icontains=self.query)
                | Q(aws_account_name__icontains=self.query)
                | Q(entra_role_name__icontains=self.query)
            )
        if self.provider_filter:
            qs = qs.filter(provider=self.provider_filter)
        if self.approval_filter:
            qs = qs.filter(requires_approval=(self.approval_filter == 'yes'))
        return qs.order_by('name')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['query'] = self.query
        context['provider_filter'] = self.provider_filter
        context['approval_filter'] = self.approval_filter
        context['filters_active'] = bool(
            self.query or self.provider_filter or self.approval_filter)
        context['total_roles'] = PrivilegedRole.objects.filter(is_active=True).count()
        # Active filters as a query string so pagination links keep them
        params = {}
        if self.query:
            params['q'] = self.query
        if self.provider_filter:
            params['provider'] = self.provider_filter
        if self.approval_filter:
            params['approval'] = self.approval_filter
        context['filter_qs'] = urlencode(params)
        return context


class RoleDetailView(LoginRequiredMixin, DetailView):
    """Show details of a privileged role."""
    model = PrivilegedRole
    template_name = 'pam/role_detail.html'
    context_object_name = 'role'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        if self.object.provider == PrivilegedRole.Provider.VAULT and self.object.vault_entry_id:
            from vault.services import active_checkout_for
            context['vault_checkout'] = active_checkout_for(
                self.request.user, self.object.vault_entry_id)
        from reviews.stats import role_usage_stats
        context['role_usage'] = role_usage_stats(self.object, days=90)
        return context
