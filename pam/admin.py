"""
Custom admin site that requires the PAM Admin role for access.

This replaces Django's default admin site to add an extra authorization
check: the user must have is_staff=True AND the PAM ADMIN role.
"""
import logging

from django.contrib import admin, messages
from django.contrib.admin import AdminSite as DjangoAdminSite
from django.http import HttpResponseRedirect
from django.urls import reverse

logger = logging.getLogger(__name__)


class PAMAdminSite(DjangoAdminSite):
    """Admin site that requires the PAM ADMIN role."""

    def has_permission(self, request):
        """Require is_staff AND PAM Admin role."""
        has_base_perm = super().has_permission(request)
        if not has_base_perm:
            return False

        # Extra check: must have the PAM ADMIN role
        user = request.user
        if not user.is_authenticated:
            return False

        if not user.is_admin_user:
            logger.warning(
                f'Blocked admin access for user={user.username} '
                f'role={user.role} — PAM Admin role required'
            )
            return False

        return True

    def login(self, request, extra_context=None):
        """Override login to redirect to the PAM login page."""
        if request.method == 'GET' and not request.user.is_authenticated:
            return HttpResponseRedirect(reverse('accounts:login'))
        return super().login(request, extra_context)

    def index(self, request, extra_context=None):
        """Show a message if the user lacks admin access."""
        if not self.has_permission(request):
            if request.user.is_authenticated:
                self.message_user(
                    request,
                    'You do not have Admin privileges to access this page.',
                    level=messages.ERROR,
                )
                return HttpResponseRedirect(reverse('requests:dashboard'))
        return super().index(request, extra_context)


# Create the singleton admin site instance
admin_site = PAMAdminSite(name='pam_admin')
