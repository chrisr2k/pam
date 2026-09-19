from django.contrib import admin

from pam.admin_site import admin_site
from .models import ScimConfig


@admin_site.register(ScimConfig)
class ScimConfigAdmin(admin.ModelAdmin):
    list_display = ('__str__', 'enabled', 'configured_at', 'configured_by')
    readonly_fields = ('configured_at', 'configured_by')
    exclude = ('bearer_token',)

    def has_add_permission(self, request):
        return not ScimConfig.objects.exists()

    def has_delete_permission(self, request, obj=None):
        return False

    def save_model(self, request, obj, form, change):
        # Keep the existing encrypted token when the field is left blank
        if change and not obj.bearer_token:
            existing = ScimConfig.objects.get(pk=obj.pk)
            obj.bearer_token = existing.bearer_token
        obj.configured_by = request.user
        super().save_model(request, obj, form, change)
