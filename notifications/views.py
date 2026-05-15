"""Views for the notification configuration page."""

import logging

from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin, UserPassesTestMixin
from django.shortcuts import redirect, render
from django.views import View

from .models import NotificationConfig

logger = logging.getLogger(__name__)


class NotificationSettingsView(LoginRequiredMixin, UserPassesTestMixin, View):
    """Admin page for configuring notification channels."""

    def test_func(self):
        return self.request.user.is_staff or self.request.user.is_admin_user

    def get(self, request):
        config = NotificationConfig.get_config()
        return render(request, 'pam/notification_settings.html', {
            'config': config,
            'is_configured': config.is_any_enabled(),
        })

    def post(self, request):
        config = NotificationConfig.get_config()

        # Email settings
        config.email_enabled = request.POST.get('email_enabled') == 'on'
        config.smtp_host = request.POST.get('smtp_host', '').strip()
        try:
            config.smtp_port = int(request.POST.get('smtp_port', 587))
        except (ValueError, TypeError):
            config.smtp_port = 587
        config.smtp_username = request.POST.get('smtp_username', '').strip()
        smtp_password = request.POST.get('smtp_password', '').strip()
        if smtp_password:
            config.smtp_password = smtp_password
        config.smtp_use_tls = request.POST.get('smtp_use_tls') == 'on'
        config.email_from = request.POST.get('email_from', '').strip()

        # Slack settings
        config.slack_enabled = request.POST.get('slack_enabled') == 'on'
        config.slack_webhook_url = request.POST.get('slack_webhook_url', '').strip()
        config.slack_channel = request.POST.get('slack_channel', '').strip()

        # Teams settings
        config.teams_enabled = request.POST.get('teams_enabled') == 'on'
        config.teams_webhook_url = request.POST.get('teams_webhook_url', '').strip()

        # Event toggles
        config.notify_on_request_created = request.POST.get('notify_on_request_created') == 'on'
        config.notify_on_request_approved = request.POST.get('notify_on_request_approved') == 'on'
        config.notify_on_request_denied = request.POST.get('notify_on_request_denied') == 'on'
        config.notify_on_access_provisioned = request.POST.get('notify_on_access_provisioned') == 'on'
        config.notify_on_access_expiring = request.POST.get('notify_on_access_expiring') == 'on'

        config.configured_by = request.user
        config.save()

        if config.is_any_enabled():
            messages.success(request, 'Notification settings saved successfully!')
        else:
            messages.warning(request, 'All notification channels are disabled. No notifications will be sent.')

        return redirect('notifications:settings')
