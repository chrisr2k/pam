"""Forms for access request creation.

The same form class validates both the direct submit path and the
MFA-challenged replay path, so re-validation at execution time is identical
to the original submission.
"""

from django import forms

from roles.models import PrivilegedRole
from .models import AccessRequest


class AccessRequestForm(forms.ModelForm):
    class Meta:
        model = AccessRequest
        fields = ['role', 'justification', 'requested_duration_minutes']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['role'].queryset = PrivilegedRole.objects.filter(is_active=True)

    def clean(self):
        cleaned = super().clean()
        role = cleaned.get('role')
        duration = cleaned.get('requested_duration_minutes')
        if role is not None and duration is not None and duration > role.max_duration_minutes:
            # Clamp rather than reject: the constraint is non-negotiable and
            # callers warn the user via the messages framework.
            cleaned['requested_duration_minutes'] = role.max_duration_minutes
        return cleaned
