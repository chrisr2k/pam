from django.contrib import admin

from pam.admin_site import admin_site
from .forms import FIELD_TO_PLUGINS, VaultEntryAdminForm
from .models import VaultEntry, VaultRotationEvent

# Structured plugin config fields (one per rotation_config key)
STRUCTURED_CONFIG_FIELDS = sorted(FIELD_TO_PLUGINS.keys())


@admin_site.register(VaultEntry)
class VaultEntryAdmin(admin.ModelAdmin):
    form = VaultEntryAdminForm
    # Inline show/hide JS (never browser-cached)
    change_form_template = 'pam/admin/vault_entry_change_form.html'
    # The custom form's extra (non-model) fields must be listed explicitly or
    # Django's admin factory drops them.
    fields = (
        ['name', 'description', 'secret_type', 'secret_value',
         'auto_rotate', 'requires_approval', 'max_checkout_minutes',
         'is_active', 'rotation_plugin', 'encrypted_value', 'last_rotated_at']
        + STRUCTURED_CONFIG_FIELDS
    )
    list_display = ('name', 'secret_type', 'auto_rotate', 'rotation_plugin',
                    'requires_approval', 'is_active', 'last_rotated_at')
    list_filter = ('secret_type', 'auto_rotate', 'rotation_plugin',
                   'requires_approval', 'is_active')
    search_fields = ('name', 'description')
    readonly_fields = ('encrypted_value', 'last_rotated_at')
    exclude = ('created_by', 'updated_by')

    def save_model(self, request, obj, form, change):
        obj.updated_by = request.user
        if not change:
            obj.created_by = request.user
        super().save_model(request, obj, form, change)


@admin_site.register(VaultRotationEvent)
class VaultRotationEventAdmin(admin.ModelAdmin):
    list_display = ('entry', 'reason', 'plugin', 'synced_to_system',
                    'rotated_by', 'rotated_at')
    list_filter = ('reason', 'plugin', 'synced_to_system')

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return request.user.is_superuser
