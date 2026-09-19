from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin, UserPassesTestMixin
from django.shortcuts import redirect, render
from django.views import View
from django.views.generic import ListView
from .models import AuditLog, SIEMConfig


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


class SIEMSettingsView(LoginRequiredMixin, UserPassesTestMixin, View):
    """Admin page for configuring SIEM export."""

    def test_func(self):
        return self.request.user.is_staff or self.request.user.is_admin_user

    def get(self, request):
        config = SIEMConfig.get_config()
        return render(request, 'pam/siem_settings.html', {
            'config': config,
            'action_choices': AuditLog.Action.choices,
        })

    def post(self, request):
        config = SIEMConfig.get_config()

        config.enabled = request.POST.get('enabled') == 'on'
        config.webhook_url = request.POST.get('webhook_url', '').strip()
        config.payload_mode = request.POST.get(
            'payload_mode', SIEMConfig.PayloadMode.SPLUNK_HEC)
        raw_token = request.POST.get('api_token', '').strip()
        if raw_token:
            config.set_api_token(raw_token)
        config.token_header = request.POST.get('token_header', 'Authorization').strip()
        config.token_prefix = request.POST.get('token_prefix', 'Splunk ').strip()
        config.action_filter = request.POST.get('action_filter', '').strip()

        config.configured_by = request.user
        config.save()

        if config.enabled and config.webhook_url:
            messages.success(request, 'SIEM settings saved successfully!')
        elif config.enabled:
            messages.warning(request, 'SIEM export is enabled but no webhook URL is set.')
        else:
            messages.info(request, 'SIEM export is disabled.')
        return redirect('audit:siem_settings')
