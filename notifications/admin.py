from django.contrib import admin
from django.shortcuts import redirect
from django.urls import reverse
from .models import NotificationConfig


@admin.register(NotificationConfig)
class NotificationConfigAdmin(admin.ModelAdmin):
    list_display = ('email_enabled', 'slack_enabled', 'teams_enabled', 'configured_at', 'configured_by')
    readonly_fields = ('configured_at', 'configured_by')
    fieldsets = (
        ('Email', {
            'fields': (
                'email_enabled', 'smtp_host', 'smtp_port', 'smtp_username',
                'smtp_password', 'smtp_use_tls', 'email_from',
            ),
        }),
        ('Slack', {
            'fields': ('slack_enabled', 'slack_webhook_url', 'slack_channel'),
        }),
        ('Microsoft Teams', {
            'fields': ('teams_enabled', 'teams_webhook_url'),
        }),
        ('Notification Events', {
            'fields': (
                'notify_on_request_created', 'notify_on_request_approved',
                'notify_on_request_denied', 'notify_on_access_provisioned',
                'notify_on_access_expiring',
            ),
        }),
        ('Metadata', {
            'fields': ('configured_at', 'configured_by'),
            'classes': ('collapse',),
        }),
    )

    def get_form(self, request, obj=None, **kwargs):
        form = super().get_form(request, obj, **kwargs)
        if 'smtp_password' in form.base_fields:
            form.base_fields['smtp_password'].widget = admin.widgets.AdminTextInputWidget(
                attrs={'type': 'password', 'autocomplete': 'off'}
            )
        return form

    def has_add_permission(self, request):
        return not NotificationConfig.objects.exists()

    def has_delete_permission(self, request, obj=None):
        return False

    def changelist_view(self, request, extra_context=None):
        config = NotificationConfig.get_config()
        if config.pk:
            return redirect(
                reverse('admin:notifications_notificationconfig_change', args=[config.pk])
            )
        return super().changelist_view(request, extra_context)

    def save_model(self, request, obj, form, change):
        obj.configured_by = request.user
        super().save_model(request, obj, form, change)
