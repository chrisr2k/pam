"""
Middleware that restricts admin access to whitelisted IPs.

Only activates when PAM_ADMIN_ALLOWED_IPS env var is set.
Configure via PAM_ADMIN_ALLOWED_IPS env var (comma-separated IPs/CIDRs).
"""
import ipaddress
import logging
import os

from django.http import HttpResponseForbidden

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


class AdminIPWhitelistMiddleware:
    """Middleware that restricts admin access to whitelisted IPs.

    Only activates when PAM_ADMIN_ALLOWED_IPS env var is set.
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
