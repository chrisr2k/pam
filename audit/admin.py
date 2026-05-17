from django.contrib import admin

from pam.admin import admin_site
from .models import AuditLog


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
