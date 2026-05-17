"""
Custom admin site configuration.

The admin_site singleton is defined in admin_site.py to avoid circular imports.
This module re-exports it and adds the authorization logic via middleware.
"""
import logging

from django.contrib import messages
from django.http import HttpResponseRedirect
from django.urls import reverse

from .admin_site import admin_site  # noqa: F401 - re-exported for convenience

logger = logging.getLogger(__name__)


def admin_login_redirect(request):
    """Redirect to the PAM login page if not authenticated."""
    if request.method == 'GET' and not request.user.is_authenticated:
        return HttpResponseRedirect(reverse('accounts:login'))
    return None


def check_admin_permission(request):
    """Check if the user has admin permission. Returns error response or None."""
    if not request.user.is_authenticated:
        return HttpResponseRedirect(reverse('accounts:login'))

    if not request.user.is_staff:
        return None  # Let Django handle this

    if not request.user.is_admin_user:
        logger.warning(
            f'Blocked admin access for user={request.user.username} '
            f'role={request.user.role} — PAM Admin role required'
        )
        return None  # Let the admin site handle the message

    return None
