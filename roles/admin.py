from django import forms
from django.contrib import admin

from pam.admin import admin_site
from .models import PrivilegedRole


class PrivilegedRoleForm(forms.ModelForm):
    class Meta:
        model = PrivilegedRole
        fields = '__all__'
        widgets = {
            'aws_permission_set_arn': forms.TextInput(attrs={
                'data-provider-field': 'AWS',
                'style': 'width: 600px;',
            }),
            'aws_account_id': forms.TextInput(attrs={
                'data-provider-field': 'AWS',
            }),
            'aws_account_name': forms.TextInput(attrs={
                'data-provider-field': 'AWS',
            }),
            'entra_role_id': forms.TextInput(attrs={
                'data-provider-field': 'ENTRA',
            }),
            'entra_role_name': forms.TextInput(attrs={
                'data-provider-field': 'ENTRA',
            }),
        }

    def clean(self):
        cleaned_data = super().clean()
        provider = cleaned_data.get('provider')

        if provider == PrivilegedRole.Provider.AWS:
            if not cleaned_data.get('aws_permission_set_arn'):
                self.add_error('aws_permission_set_arn', 'Permission Set ARN is required for AWS roles.')
            # Clear Entra fields for AWS roles
            cleaned_data['entra_role_id'] = ''
            cleaned_data['entra_role_name'] = ''

        elif provider == PrivilegedRole.Provider.ENTRA:
            if not cleaned_data.get('entra_role_id'):
                self.add_error('entra_role_id', 'Entra ID Role ID is required for Entra roles.')
            # Clear AWS fields for Entra roles
            cleaned_data['aws_permission_set_arn'] = ''
            cleaned_data['aws_account_id'] = ''
            cleaned_data['aws_account_name'] = ''

        return cleaned_data


@admin_site.register(PrivilegedRole)
class PrivilegedRoleAdmin(admin.ModelAdmin):
    form = PrivilegedRoleForm
    list_display = ('name', 'provider', 'requires_approval', 'max_duration_minutes', 'is_active')
    list_filter = ('provider', 'requires_approval', 'is_active')
    search_fields = ('name', 'description', 'aws_permission_set_arn', 'entra_role_name')
    filter_horizontal = ('approvers',)
    fieldsets = (
        (None, {
            'fields': ('name', 'description', 'provider', 'is_active'),
        }),
        ('AWS Identity Center', {
            'classes': ('aws-fields',),
            'fields': ('aws_permission_set_arn', 'aws_account_id', 'aws_account_name'),
            'description': 'Required for AWS roles',
        }),
        ('Entra ID PIM', {
            'classes': ('entra-fields',),
            'fields': ('entra_role_id', 'entra_role_name'),
            'description': 'Required for Entra ID roles',
        }),
        ('Policy', {
            'fields': ('requires_approval', 'max_duration_minutes', 'approvers'),
        }),
    )

    class Media:
        js = ('js/admin_role_fields.js',)
