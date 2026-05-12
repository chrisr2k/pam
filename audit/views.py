from django.contrib.auth.mixins import LoginRequiredMixin, UserPassesTestMixin
from django.views.generic import ListView
from .models import AuditLog


class AuditLogListView(LoginRequiredMixin, UserPassesTestMixin, ListView):
    """View audit log entries (Auditor and Admin only)."""
    model = AuditLog
    template_name = 'pam/audit_log.html'
    context_object_name = 'logs'
    paginate_by = 50

    def test_func(self):
        return self.request.user.is_auditor or self.request.user.is_admin_user

    def get_queryset(self):
        qs = AuditLog.objects.select_related('actor')
        action = self.request.GET.get('action')
        if action:
            qs = qs.filter(action=action)
        return qs
