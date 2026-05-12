import logging
from django.utils import timezone

logger = logging.getLogger(__name__)


class AuditMiddleware:
    """Middleware to log requests for audit purposes."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        return response

    def process_view(self, request, view_func, view_args, view_kwargs):
        """Log significant actions."""
        return None


def log_action(actor, action, target_type='', target_id='', details=None, request=None):
    """Helper function to create audit log entries."""
    from .models import AuditLog

    ip_address = None
    if request:
        ip_address = request.META.get('REMOTE_ADDR')

    AuditLog.objects.create(
        actor=actor,
        action=action,
        target_type=target_type,
        target_id=str(target_id) if target_id else '',
        details=details or {},
        ip_address=ip_address,
    )
