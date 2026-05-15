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
    readonly_fields = ('configured_at', 'configured_by', 'client_secret_display')
    fieldsets = (
        (None, {
            'fields': ('tenant_id', 'client_id', 'client_secret', 'redirect_uri'),
        }),
        ('Metadata', {
            'fields': ('configured_at', 'configured_by'),
            'classes': ('collapse',),
        }),
    )
    # Exclude the raw client_secret from the form; use a custom field instead
    exclude = ('client_secret',)

    def get_fieldsets(self, request, obj=None):
        """Override to include client_secret_display in the form."""
        fieldsets = super().get_fieldsets(request, obj)
        if obj and obj.client_secret:
            # Show masked display field when secret exists
            fieldsets[0][1]['fields'] = ('tenant_id', 'client_id', 'client_secret_display', 'redirect_uri')
        else:
            # Show input field when no secret exists
            fieldsets[0][1]['fields'] = ('tenant_id', 'client_id', 'client_secret', 'redirect_uri')
        return fieldsets

    def get_form(self, request, obj=None, **kwargs):
        form = super().get_form(request, obj, **kwargs)
        if 'client_secret' in form.base_fields:
            form.base_fields['client_secret'].widget = admin.widgets.AdminTextInputWidget(
                attrs={'type': 'password', 'autocomplete': 'off', 'placeholder': 'Enter new client secret'}
            )
            form.base_fields['client_secret'].required = False
            form.base_fields['client_secret'].help_text = 'Leave blank to keep the existing encrypted secret'
        return form

    def client_secret_display(self, obj):
        """Display a masked version of the client secret."""
        if obj and obj.client_secret:
            return format_html(
                '<input type="password" class="vTextField" value="{}" readonly '
                'style="background:#f0f0f0; cursor:not-allowed;" '
                'title="The client secret is encrypted at rest and cannot be viewed">',
                '••••••••••••••••'
            )
        return 'Not configured'
    client_secret_display.short_description = 'Client Secret'

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
        # Only update the secret if a new value was provided
        raw_secret = form.cleaned_data.get('client_secret', '')
        if raw_secret:
            obj.set_client_secret(raw_secret)
        else:
            # Keep the existing encrypted secret
            existing = EntraConfig.get_config()
            obj.client_secret = existing.client_secret
        super().save_model(request, obj, form, change)
