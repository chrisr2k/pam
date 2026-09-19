"""Forms for access review campaigns."""

from django import forms
from django.contrib.auth import get_user_model
from django.utils import timezone

from .models import AccessReview

User = get_user_model()


class ReviewCreateForm(forms.ModelForm):
    """Create a recertification campaign, optionally filtered to unused access."""

    reviewers = forms.ModelMultipleChoiceField(
        queryset=User.objects.filter(is_active=True),
        required=False,
        help_text='Users assigned to review access.',
    )
    due_date = forms.DateTimeField(
        widget=forms.DateTimeInput(attrs={'type': 'datetime-local'},
                                   format='%Y-%m-%dT%H:%M'),
        input_formats=['%Y-%m-%dT%H:%M'],
    )
    unused_days = forms.IntegerField(
        required=False, min_value=1,
        label='Only include access unused for N days',
        help_text='Optional: role-mining filter — only entitlements whose most '
                  'recent grant is older than this many days are included.',
    )

    class Meta:
        model = AccessReview
        fields = ['name', 'description', 'due_date']

    def clean_due_date(self):
        due = self.cleaned_data.get('due_date')
        if due and timezone.is_naive(due):
            due = timezone.make_aware(due)
        return due
