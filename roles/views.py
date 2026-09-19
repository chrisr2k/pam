from django.contrib.auth.mixins import LoginRequiredMixin
from django.views.generic import ListView, DetailView
from .models import PrivilegedRole


class RoleListView(LoginRequiredMixin, ListView):
    """List all available privileged roles."""
    model = PrivilegedRole
    template_name = 'pam/role_list.html'
    context_object_name = 'roles'

    def get_queryset(self):
        return PrivilegedRole.objects.filter(is_active=True)


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
