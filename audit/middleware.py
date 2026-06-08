import logging
from django.utils import timezone

logger = logging.getLogger(__name__)


class AuditMiddleware:
    """Middleware to log requests for audit purposes."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Check for expired sessions on every request as a fallback
        # when Celery Beat is not running
        self._check_expired_sessions()
        response = self.get_response(request)
        return response

    def _check_expired_sessions(self):
        """Check for and deprovision any expired access sessions."""
        try:
            from access_requests.models import AccessRequest
            from tasks.provisioning import deprovision_access_sync

            now = timezone.now()
            expired_requests = AccessRequest.objects.filter(
                status__in=[AccessRequest.Status.PROVISIONED, AccessRequest.Status.ACTIVE],
                expires_at__lte=now,
            )
            for req in expired_requests:
                logger.info(f'Middleware: deprovisioning expired request #{req.id}')
                try:
                    deprovision_access_sync(req.id)
                except Exception as e:
                    logger.exception(f'Middleware: failed to deprovision request #{req.id}: {e}')
        except Exception:
            # Silently ignore errors during startup (tables may not exist yet)
            pass

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
