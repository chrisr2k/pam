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
