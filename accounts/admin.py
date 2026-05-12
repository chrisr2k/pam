from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.shortcuts import redirect
from django.urls import reverse
from django.utils.html import format_html
from .models import User, EntraConfig


@admin.register(User)
class UserAdmin(BaseUserAdmin):
    list_display = ('username', 'email', 'role', 'entra_object_id', 'is_staff', 'is_active')
    list_filter = ('role', 'is_staff', 'is_active', 'groups')
    search_fields = ('username', 'email', 'first_name', 'last_name', 'entra_object_id')
    fieldsets = BaseUserAdmin.fieldsets + (
        ('PAM Info', {'fields': ('role', 'entra_object_id', 'manager')}),
    )


@admin.register(EntraConfig)
class EntraConfigAdmin(admin.ModelAdmin):
    list_display = ('tenant_id', 'client_id', 'configured_at', 'configured_by')
    readonly_fields = ('configured_at', 'configured_by')
    fieldsets = (
        (None, {
            'fields': ('tenant_id', 'client_id', 'client_secret', 'redirect_uri'),
        }),
        ('Metadata', {
            'fields': ('configured_at', 'configured_by'),
            'classes': ('collapse',),
        }),
    )

    def get_form(self, request, obj=None, **kwargs):
        form = super().get_form(request, obj, **kwargs)
        if 'client_secret' in form.base_fields:
            form.base_fields['client_secret'].widget = admin.widgets.AdminTextInputWidget(
                attrs={'type': 'password', 'autocomplete': 'off'}
            )
        return form

    def has_add_permission(self, request):
        return not EntraConfig.objects.exists()

    def has_delete_permission(self, request, obj=None):
        return False

    def changelist_view(self, request, extra_context=None):
        """Redirect directly to the change form since there's only one config."""
        config = EntraConfig.get_config()
        if config.pk:
            return redirect(
                reverse('admin:accounts_entraconfig_change', args=[config.pk])
            )
        return super().changelist_view(request, extra_context)

    def save_model(self, request, obj, form, change):
        obj.configured_by = request.user
        super().save_model(request, obj, form, change)
