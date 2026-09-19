"""Forms for vault entry management.

Rotation plugin configuration is edited as structured per-plugin fields
(shown/hidden by JS via data-plugin attributes) instead of a raw JSON blob.
The JSON is assembled from the selected plugin's fields in clean().
"""

from django import forms

from .models import VaultEntry
from .rotation import REQUIRED_CONFIG_KEYS, plugin_choices


def parse_header_lines(text):
    """Parse 'Name: value' lines into a headers dict (HTTP plugin)."""
    headers = {}
    for line in (text or '').splitlines():
        line = line.strip()
        if not line:
            continue
        if ':' not in line:
            raise ValueError(f"Invalid header line (expected 'Name: value'): {line}")
        name, value = line.split(':', 1)
        headers[name.strip()] = value.strip()
    return headers


def format_header_lines(headers):
    """Render a headers dict back into 'Name: value' lines."""
    if not headers:
        return ''
    return '\n'.join(f'{k}: {v}' for k, v in headers.items())


# Which plugins use each structured field (drives the JS show/hide)
PLUGIN_FIELDS = {
    'aws_iam': ('iam_user_name', 'region'),
    'entra_app_secret': ('tenant_id', 'client_id'),
    'ssh': ('host', 'username', 'port', 'use_sudo'),
    'postgresql': ('host', 'username', 'port', 'dbname'),
    'mysql': ('host', 'username', 'port', 'host_part'),
    'winrm': ('host', 'username', 'port', 'use_ssl', 'cert_validation', 'account_type'),
    'http': ('url', 'method', 'headers', 'body_template', 'success_status',
             'verify_url', 'verify_method', 'cleanup_url'),
}

FIELD_TO_PLUGINS = {}
for _plugin, _fields in PLUGIN_FIELDS.items():
    for _field in _fields:
        FIELD_TO_PLUGINS.setdefault(_field, []).append(_plugin)


class StructuredRotationConfigMixin(forms.Form):
    """Structured per-plugin rotation config fields.

    Subclasses (the web create form and the admin form) share this so both
    surfaces edit configuration the same structured way. clean() assembles
    rotation_config from the SELECTED plugin's fields only.
    """

    rotation_plugin = forms.ChoiceField(
        choices=plugin_choices, required=False,
        help_text='Vault-only generates a random value. Other plugins push '
                  'the new credential to the real system.')

    # ── Shared structured fields (one per rotation_config key) ───────────
    host = forms.CharField(max_length=255, required=False, label='Host')
    username = forms.CharField(max_length=255, required=False, label='Username')
    port = forms.IntegerField(required=False, min_value=1, label='Port',
                              help_text='Leave blank for the plugin default.')
    iam_user_name = forms.CharField(max_length=128, required=False, label='IAM user name')
    region = forms.CharField(max_length=64, required=False, label='Region',
                             initial='us-east-1')
    tenant_id = forms.CharField(max_length=128, required=False, label='Tenant ID')
    client_id = forms.CharField(max_length=128, required=False,
                                label='Client ID (app ID)')
    dbname = forms.CharField(max_length=128, required=False, label='Database name')
    host_part = forms.CharField(max_length=128, required=False,
                                label='Account host part', initial='%',
                                help_text="The account's host part, e.g. '%' or 'localhost'.")
    use_sudo = forms.BooleanField(required=False, label='Use sudo', initial=True,
                                  help_text='Change the password via sudo chpasswd.')
    use_ssl = forms.BooleanField(required=False, label='Use HTTPS', initial=True)
    cert_validation = forms.ChoiceField(
        required=False, label='Certificate validation',
        choices=(('ignore', 'Ignore (self-signed)'), ('validate', 'Validate')),
        initial='ignore')
    account_type = forms.ChoiceField(
        required=False, label='Account type',
        choices=(('local', 'Local account'), ('ad', 'Active Directory')),
        initial='local')
    url = forms.CharField(max_length=512, required=False, label='URL')
    method = forms.CharField(max_length=10, required=False, label='HTTP method',
                             initial='POST')
    headers = forms.CharField(
        required=False, label='Headers',
        widget=forms.Textarea(attrs={'rows': 3}),
        help_text="One 'Name: value' per line, e.g. 'Authorization: Bearer xyz'.")
    body_template = forms.CharField(
        required=False, label='Body template',
        widget=forms.Textarea(attrs={'rows': 3}),
        help_text='Use {old_value} and {new_value} placeholders.')
    success_status = forms.CharField(max_length=64, required=False,
                                     label='Success status', initial='200',
                                     help_text='HTTP status that counts as success.')
    verify_url = forms.CharField(max_length=512, required=False, label='Verify URL',
                                 help_text='Optional request made with the new value.')
    verify_method = forms.CharField(max_length=10, required=False,
                                    label='Verify method', initial='GET')
    cleanup_url = forms.CharField(max_length=512, required=False, label='Cleanup URL',
                                  help_text='Optional request made after the store.')

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Prefill structured fields from an existing instance's config
        instance = kwargs.get('instance')
        if instance is not None:
            config = instance.rotation_config or {}
            for key, value in config.items():
                if key == 'headers':
                    value = format_header_lines(value)
                if key in self.fields:
                    self.fields[key].initial = value
                    self.initial[key] = value
        # data-plugin attributes drive the JS show/hide
        for name in FIELD_TO_PLUGINS:
            field = self.fields.get(name)
            if field is not None:
                field.widget.attrs['data-plugin'] = ' '.join(FIELD_TO_PLUGINS[name])

    def clean(self):
        cleaned = super().clean()
        plugin = cleaned.get('rotation_plugin') or ''
        config = {}
        for key in PLUGIN_FIELDS.get(plugin, ()):
            value = cleaned.get(key)
            if key == 'headers' and value:
                try:
                    value = parse_header_lines(value)
                except ValueError as e:
                    self.add_error('headers', str(e))
                    continue
            if key in ('use_sudo', 'use_ssl'):
                config[key] = bool(value)  # explicit False overrides the runtime default
            elif value not in (None, ''):
                config[key] = value
        cleaned['rotation_config'] = config
        for key in REQUIRED_CONFIG_KEYS.get(plugin, ()):
            if not config.get(key):
                self.add_error(key, f'The {plugin} plugin requires this field.')
        return cleaned

    def save(self, commit=True):
        instance = super().save(commit=False)
        instance.rotation_config = self.cleaned_data.get('rotation_config') or {}
        if commit:
            instance.save()
        return instance


class VaultEntryForm(StructuredRotationConfigMixin, forms.ModelForm):
    """Create a vault entry; the secret value is never re-displayed."""

    value = forms.CharField(
        label='Secret value',
        widget=forms.PasswordInput(attrs={'autocomplete': 'new-password'}),
        help_text='Stored encrypted at rest; never displayed again. For rotation '
                  'plugins this must be the CURRENT live credential.',
    )

    class Meta:
        model = VaultEntry
        fields = [
            'name', 'description', 'secret_type',
            'auto_rotate', 'requires_approval', 'max_checkout_minutes',
            'rotation_plugin',
        ]


class VaultEntryAdminForm(StructuredRotationConfigMixin, forms.ModelForm):
    """Django-admin edit form: structured plugin config, encrypted value readonly.

    The secret itself is entered via `secret_value` on creation only (the
    encrypted field is readonly and excluded from add views by Django).
    """

    secret_value = forms.CharField(
        required=False, label='Secret value',
        widget=forms.PasswordInput(attrs={'autocomplete': 'new-password'}),
        help_text='Set on creation only; stored encrypted at rest and never '
                  'shown again. Leave blank when editing to keep the current value.',
    )

    class Meta:
        model = VaultEntry
        fields = [
            'name', 'description', 'secret_type',
            'auto_rotate', 'requires_approval', 'max_checkout_minutes',
            'is_active', 'rotation_plugin', 'encrypted_value',
        ]

    def save(self, commit=True):
        instance = super().save(commit=False)
        secret = self.cleaned_data.get('secret_value')
        if secret:
            instance.set_secret_value(secret)
        if commit:
            instance.save()
        return instance
