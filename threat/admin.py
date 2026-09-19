from django.contrib import admin

from pam.admin_site import admin_site
from .models import ThreatAlert, ThreatConfig


@admin_site.register(ThreatAlert)
class ThreatAlertAdmin(admin.ModelAdmin):
    list_display = ('created_at', 'severity', 'rule', 'summary', 'acknowledged_at')
    list_filter = ('severity', 'rule', 'acknowledged_at')
    search_fields = ('summary', 'dedup_key', 'details')
    date_hierarchy = 'created_at'
    readonly_fields = ('rule', 'severity', 'summary', 'details', 'dedup_key',
                       'related_audit_ids', 'created_at')

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return request.user.is_superuser


@admin_site.register(ThreatConfig)
class ThreatConfigAdmin(admin.ModelAdmin):
    readonly_fields = ('last_run_at', 'configured_at', 'configured_by')

    def has_add_permission(self, request):
        return not ThreatConfig.objects.exists()

    def has_delete_permission(self, request, obj=None):
        return False

    def save_model(self, request, obj, form, change):
        obj.configured_by = request.user
        super().save_model(request, obj, form, change)
