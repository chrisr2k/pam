"""Threat analytics views: alerts list, settings, acknowledge."""

import re

from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin, UserPassesTestMixin
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.views import View
from django.views.generic import ListView

from .models import ThreatAlert, ThreatConfig
from .rules import RULES

TIME_RE = re.compile(r'^([01]\d|2[0-3]):[0-5]\d$')


class _StaffTestMixin(UserPassesTestMixin):
    def test_func(self):
        return self.request.user.is_staff or self.request.user.is_admin_user


class ThreatAlertListView(LoginRequiredMixin, _StaffTestMixin, ListView):
    """Recent threat alerts (staff/admins)."""

    model = ThreatAlert
    template_name = 'pam/threat_alerts.html'
    context_object_name = 'alerts'
    paginate_by = 50

    def get_queryset(self):
        qs = ThreatAlert.objects.select_related('acknowledged_by')
        rule = self.request.GET.get('rule')
        if rule in RULES:
            qs = qs.filter(rule=rule)
        return qs

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['rule_choices'] = [('', 'All rules')] + [
            (name, rule.label) for name, rule in RULES.items()]
        context['active_rule'] = self.request.GET.get('rule', '')
        return context


class ThreatSettingsView(LoginRequiredMixin, _StaffTestMixin, View):
    """Staff page for tuning detection rules and thresholds."""

    def get(self, request):
        config = ThreatConfig.get_config()
        return render(request, 'pam/threat_settings.html', {
            'config': config,
            'rules': RULES,
        })

    def post(self, request):
        config = ThreatConfig.get_config()

        config.scan_enabled = request.POST.get('scan_enabled') == 'on'
        cooldown = request.POST.get('cooldown_minutes', '')
        try:
            config.cooldown_minutes = max(1, int(cooldown))
        except (ValueError, TypeError):
            pass

        int_fields = [
            'impossible_travel_window_minutes', 'impossible_travel_min_distinct_ips',
            'off_hours_window_minutes',
            'mfa_storm_threshold', 'mfa_storm_window_minutes',
            'checkout_spike_threshold', 'checkout_spike_window_minutes',
            'reveal_spike_threshold', 'reveal_spike_window_minutes',
        ]
        for field in int_fields:
            raw = request.POST.get(field, '')
            try:
                setattr(config, field, max(1, int(raw)))
            except (ValueError, TypeError):
                pass  # keep the previous value

        for rule_name in ('impossible_travel', 'off_hours_elevation', 'mfa_storm',
                          'checkout_spike', 'reveal_spike'):
            enabled_field, _ = ThreatConfig.RULE_FIELDS[rule_name]
            setattr(config, enabled_field, request.POST.get(enabled_field) == 'on')

        start = request.POST.get('off_hours_start', '')
        if TIME_RE.match(start):
            config.off_hours_start = start
        end = request.POST.get('off_hours_end', '')
        if TIME_RE.match(end):
            config.off_hours_end = end
        config.off_hours_weekend = request.POST.get('off_hours_weekend') == 'on'

        config.configured_by = request.user
        config.save()
        messages.success(request, 'Threat settings saved successfully.')
        return redirect('threat:settings')


class ThreatAcknowledgeView(LoginRequiredMixin, _StaffTestMixin, View):
    """POST: mark an alert as acknowledged (idempotent)."""

    def get(self, request, pk):
        return redirect('threat:list')

    def post(self, request, pk):
        alert = get_object_or_404(ThreatAlert, pk=pk)
        if not alert.acknowledged_at:
            alert.acknowledged_by = request.user
            alert.acknowledged_at = timezone.now()
            alert.save(update_fields=['acknowledged_by', 'acknowledged_at'])
            messages.success(request, f'Alert #{alert.pk} acknowledged.')
        return redirect('threat:list')
