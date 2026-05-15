"""Models for notification configuration (Email, Slack, Teams)."""

from django.db import models
from django.conf import settings


class NotificationConfig(models.Model):
    """Singleton model for notification channel configuration."""

    # Email settings
    email_enabled = models.BooleanField(default=False, verbose_name='Enable Email Notifications')
    smtp_host = models.CharField(max_length=256, blank=True, default='', verbose_name='SMTP Host')
    smtp_port = models.PositiveIntegerField(default=587, verbose_name='SMTP Port')
    smtp_username = models.CharField(max_length=256, blank=True, default='', verbose_name='SMTP Username')
    smtp_password = models.CharField(max_length=512, blank=True, default='', verbose_name='SMTP Password')
    smtp_use_tls = models.BooleanField(default=True, verbose_name='Use TLS')
    email_from = models.CharField(
        max_length=256, blank=True, default='',
        verbose_name='From Address',
        help_text='Email address used as the sender',
    )

    # Slack settings
    slack_enabled = models.BooleanField(default=False, verbose_name='Enable Slack Notifications')
    slack_webhook_url = models.CharField(
        max_length=512, blank=True, default='',
        verbose_name='Slack Webhook URL',
        help_text='Incoming webhook URL from Slack Apps',
    )
    slack_channel = models.CharField(
        max_length=128, blank=True, default='',
        verbose_name='Slack Channel',
        help_text='e.g. #pam-notifications',
    )

    # Microsoft Teams settings
    teams_enabled = models.BooleanField(default=False, verbose_name='Enable Teams Notifications')
    teams_webhook_url = models.CharField(
        max_length=512, blank=True, default='',
        verbose_name='Teams Webhook URL',
        help_text='Incoming webhook URL from Teams Connector',
    )

    # Notification events
    notify_on_request_created = models.BooleanField(
        default=True, verbose_name='Request Created',
        help_text='Send notification when a new access request is submitted',
    )
    notify_on_request_approved = models.BooleanField(
        default=True, verbose_name='Request Approved',
        help_text='Send notification when a request is approved',
    )
    notify_on_request_denied = models.BooleanField(
        default=True, verbose_name='Request Denied',
        help_text='Send notification when a request is denied',
    )
    notify_on_access_provisioned = models.BooleanField(
        default=True, verbose_name='Access Provisioned',
        help_text='Send notification when access has been provisioned',
    )
    notify_on_access_expiring = models.BooleanField(
        default=False, verbose_name='Access Expiring Soon',
        help_text='Send notification when access is about to expire',
    )

    configured_at = models.DateTimeField(auto_now=True)
    configured_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL,
        null=True, blank=True, verbose_name='Configured by',
    )

    class Meta:
        verbose_name = 'Notification Configuration'
        verbose_name_plural = 'Notification Configuration'

    def __str__(self):
        channels = []
        if self.email_enabled:
            channels.append('Email')
        if self.slack_enabled:
            channels.append('Slack')
        if self.teams_enabled:
            channels.append('Teams')
        return f'Notifications: {", ".join(channels) or "Not configured"}'

    def save(self, *args, **kwargs):
        self.pk = 1  # Singleton
        super().save(*args, **kwargs)

    @classmethod
    def get_config(cls):
        config, _ = cls.objects.get_or_create(pk=1)
        return config

    def is_any_enabled(self) -> bool:
        return self.email_enabled or self.slack_enabled or self.teams_enabled
