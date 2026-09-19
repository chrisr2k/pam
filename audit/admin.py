from django.contrib import admin

from pam.admin_site import admin_site
from .models import AuditLog, SIEMConfig


@admin_site.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ('timestamp', 'actor', 'action', 'target_type', 'target_id')
    list_filter = ('action', 'timestamp')
    search_fields = ('actor__username', 'target_type', 'target_id', 'details')
    date_hierarchy = 'timestamp'
    readonly_fields = ('timestamp',)

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return request.user.is_superuser


@admin_site.register(SIEMConfig)
class SIEMConfigAdmin(admin.ModelAdmin):
    list_display = ('__str__', 'payload_mode', 'enabled', 'watermark', 'last_success_at')
    readonly_fields = (
        'watermark', 'last_error', 'last_error_at',
        'last_run_at', 'last_success_at', 'configured_at', 'configured_by',
    )
    exclude = ('api_token',)

    def has_add_permission(self, request):
        return not SIEMConfig.objects.exists()

    def has_delete_permission(self, request, obj=None):
        return False

    def save_model(self, request, obj, form, change):
        # Keep the existing encrypted token when the field is left blank
        if change and not obj.api_token:
            existing = SIEMConfig.objects.get(pk=obj.pk)
            obj.api_token = existing.api_token
        obj.configured_by = request.user
        super().save_model(request, obj, form, change)
