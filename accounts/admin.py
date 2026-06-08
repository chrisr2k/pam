from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.shortcuts import redirect
from django.urls import reverse
from django.utils.html import format_html

from pam.admin_site import admin_site
from .models import User, EntraConfig, AWSConfig



@admin_site.register(User)
class UserAdmin(BaseUserAdmin):
    list_display = ('username', 'email', 'role', 'entra_object_id', 'is_staff', 'is_active')
    list_filter = ('role', 'is_staff', 'is_active', 'groups')
    search_fields = ('username', 'email', 'first_name', 'last_name', 'entra_object_id')
    fieldsets = BaseUserAdmin.fieldsets + (
        ('PAM Info', {'fields': ('role', 'entra_object_id', 'manager')}),
    )


@admin_site.register(EntraConfig)
class EntraConfigAdmin(admin.ModelAdmin):
    list_display = ('tenant_id', 'client_id', 'configured_at', 'configured_by')
    readonly_fields = ('configured_at', 'configured_by', 'client_secret_display', 'pim_client_secret_display')

    def get_fieldsets(self, request, obj=None):
        """Override to include PIM fields and secret display."""
        oidc_fields = ['tenant_id', 'client_id']
        pim_fields = ['pim_tenant_id', 'pim_client_id']

        if obj and obj.client_secret:
            oidc_fields.append('client_secret_display')
        else:
            oidc_fields.append('client_secret')
        oidc_fields.append('redirect_uri')

        if obj and obj.pim_client_secret:
            pim_fields.append('pim_client_secret_display')
        else:
            pim_fields.append('pim_client_secret')

        return (
            ('OIDC Login App', {
                'fields': oidc_fields,
                'description': 'Used for user authentication. Needs only User.Read delegated permission.',
            }),
            ('PIM Management App', {
                'fields': pim_fields,
                'description': 'Separate app for role management. Needs RoleManagement.ReadWrite.Directory '
                               'application permission. Leave blank to reuse OIDC app (dev only).',
                'classes': ('wide',),
            }),
            ('Metadata', {
                'fields': ('configured_at', 'configured_by'),
                'classes': ('collapse',),
            }),
        )

    # Exclude raw secret fields from the default form; use custom display fields
    exclude = ('client_secret', 'pim_client_secret')

    def get_form(self, request, obj=None, **kwargs):
        form = super().get_form(request, obj, **kwargs)
        for field_name in ('client_secret', 'pim_client_secret'):
            if field_name in form.base_fields:
                form.base_fields[field_name].widget = admin.widgets.AdminTextInputWidget(
                    attrs={'type': 'password', 'autocomplete': 'off', 'placeholder': 'Enter new secret'}
                )
                form.base_fields[field_name].required = False
                form.base_fields[field_name].help_text = 'Leave blank to keep the existing encrypted secret'
        return form

    def client_secret_display(self, obj):
        """Display a masked version of the OIDC client secret."""
        if obj and obj.client_secret:
            return format_html(
                '<input type="password" class="vTextField" value="{}" readonly '
                'style="background:#f0f0f0; cursor:not-allowed;" '
                'title="The client secret is encrypted at rest and cannot be viewed">',
                '••••••••••••••••'
            )
        return 'Not configured'
    client_secret_display.short_description = 'OIDC Client Secret'

    def pim_client_secret_display(self, obj):
        """Display a masked version of the PIM client secret."""
        if obj and obj.pim_client_secret:
            return format_html(
                '<input type="password" class="vTextField" value="{}" readonly '
                'style="background:#f0f0f0; cursor:not-allowed;" '
                'title="The PIM client secret is encrypted at rest and cannot be viewed">',
                '••••••••••••••••'
            )
        return 'Not configured'
    pim_client_secret_display.short_description = 'PIM Client Secret'

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
        # Only update secrets if new values were provided
        for secret_field in ('client_secret', 'pim_client_secret'):
            raw_secret = form.cleaned_data.get(secret_field, '')
            if raw_secret:
                if secret_field == 'client_secret':
                    obj.set_client_secret(raw_secret)
                else:
                    obj.set_pim_client_secret(raw_secret)
            else:
                # Keep the existing encrypted secret
                existing = EntraConfig.get_config()
                setattr(obj, secret_field, getattr(existing, secret_field))
        super().save_model(request, obj, form, change)


@admin_site.register(AWSConfig)
class AWSConfigAdmin(admin.ModelAdmin):
    list_display = ('sso_instance_arn', 'region', 'auth_method_display', 'configured_at', 'configured_by')
    readonly_fields = ('configured_at', 'configured_by')

    fieldsets = (
        ('SSO Instance', {
            'fields': ('sso_instance_arn', 'region'),
            'description': 'AWS IAM Identity Center instance configuration.',
        }),
        ('STS AssumeRole (Best for cross-account)', {
            'fields': ('role_arn', 'role_session_name', 'external_id'),
            'description': 'PAM will call STS AssumeRole to get temporary credentials. '
                           'The role must trust PAM\'s current identity.',
            'classes': ('wide',),
        }),
        ('IAM Roles Anywhere (Best for on-prem / OCI)', {
            'fields': ('roles_anywhere_profile_arn', 'roles_anywhere_trust_arn'),
            'description': 'Requires a certificate + private key configured via .env: '
                           'AWS_ROLES_ANYWHERE_CERT_PATH and AWS_ROLES_ANYWHERE_KEY_PATH',
            'classes': ('wide',),
        }),
        ('IAM User Keys (Dev only - fallback)', {
            'fields': ('access_key_id', 'secret_access_key'),
            'description': 'Long-lived IAM user credentials. Only use for development.',
            'classes': ('wide',),
        }),
        ('Metadata', {
            'fields': ('configured_at', 'configured_by'),
            'classes': ('collapse',),
        }),
    )

    def auth_method_display(self, obj):
        """Show the detected auth method."""
        if not obj.pk:
            return ''
        method = obj.get_auth_method()
        badges = {
            'instance_profile': ('success', 'Instance Profile'),
            'roles_anywhere': ('info', 'Roles Anywhere'),
            'assume_role': ('primary', 'STS AssumeRole'),
            'iam_user': ('warning', 'IAM User Keys'),
        }
        color, label = badges.get(method, ('secondary', method))
        return format_html('<span class="badge bg-{}">{}</span>', color, label)
    auth_method_display.short_description = 'Auth Method'

    def has_add_permission(self, request):
        return not AWSConfig.objects.exists()

    def has_delete_permission(self, request, obj=None):
        return False

    def changelist_view(self, request, extra_context=None):
        """Redirect directly to the change form since there's only one config."""
        config = AWSConfig.get_config()
        if config.pk:
            return redirect(
                reverse('admin:accounts_awsconfig_change', args=[config.pk])
            )
        return super().changelist_view(request, extra_context)

    def save_model(self, request, obj, form, change):
        obj.configured_by = request.user
        super().save_model(request, obj, form, change)


