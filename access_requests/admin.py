from django.contrib import admin
from .models import AccessRequest, Approval


@admin.register(AccessRequest)
class AccessRequestAdmin(admin.ModelAdmin):
    list_display = ('id', 'requester', 'role', 'status', 'requested_duration_minutes', 'created_at')
    list_filter = ('status', 'role__provider')
    search_fields = ('requester__username', 'requester__email', 'justification')
    date_hierarchy = 'created_at'
    readonly_fields = ('created_at', 'updated_at', 'provisioned_at', 'expires_at', 'deprovisioned_at')


@admin.register(Approval)
class ApprovalAdmin(admin.ModelAdmin):
    list_display = ('request', 'approver', 'decision', 'decided_at')
    list_filter = ('decision',)
    search_fields = ('approver__username', 'request__id')
