"""
Custom admin site that requires the PAM Admin role for access.

This replaces Django's default admin site to add an extra authorization
check: the user must have is_staff=True AND the PAM ADMIN role.

Also supports optional IP whitelisting via the PAM_ADMIN_ALLOWED_IPS
environment variable (comma-separated IPs or CIDR ranges).
"""
import ipaddress
import logging
import os

from django.contrib import admin, messages
from django.contrib.admin import AdminSite as DjangoAdminSite
from django.http import HttpResponseForbidden, HttpResponseRedirect
from django.urls import reverse

logger = logging.getLogger(__name__)


def _get_client_ip(request):
    """Extract the client IP from the request, respecting proxy headers."""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        return x_forwarded_for.split(',')[0].strip()
    return request.META.get('REMOTE_ADDR', '')


def _ip_is_allowed(ip_str: str, allowed_list: list) -> bool:
    """Check if an IP string matches any entry in the allowed list."""
    if not ip_str:
        return False
    try:
        client_ip = ipaddress.ip_address(ip_str)
        for entry in allowed_list:
            entry = entry.strip()
            if not entry:
                continue
            try:
                network = ipaddress.ip_network(entry, strict=False)
                if client_ip in network:
                    return True
            except ValueError:
                # If it's a single IP, compare directly
                if entry == ip_str:
                    return True
    except ValueError:
        pass
    return False


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


# ─── Optional IP whitelist middleware ──────────────────────────────────────
# Applied as a wrapper around the admin site's wsgi handler.
# Configure via PAM_ADMIN_ALLOWED_IPS env var (comma-separated IPs/CIDRs).


class AdminIPWhitelistMiddleware:
    """Middleware that restricts admin access to whitelisted IPs.

    Only activates when PAM_ADMIN_ALLOWED_IPS env var is set.
    Applied as a WSGI wrapper rather than Django middleware so it
    runs before any Django processing.
    """

    def __init__(self, get_response):
        self.get_response = get_response
        raw_ips = os.getenv('PAM_ADMIN_ALLOWED_IPS', '').strip()
        self.allowed_ips = [ip.strip() for ip in raw_ips.split(',') if ip.strip()] if raw_ips else []
        self.enabled = bool(self.allowed_ips)
        if self.enabled:
            logger.info(
                f'Admin IP whitelist enabled: {len(self.allowed_ips)} IP(s)/CIDR(s) configured'
            )

    def __call__(self, request):
        if self.enabled and request.path.startswith('/pam-admin'):
            client_ip = _get_client_ip(request)
            if not _ip_is_allowed(client_ip, self.allowed_ips):
                logger.warning(
                    f'Blocked admin access from IP={client_ip} '
                    f'(not in PAM_ADMIN_ALLOWED_IPS whitelist)'
                )
                return HttpResponseForbidden('Administrative access restricted')
        return self.get_response(request)
