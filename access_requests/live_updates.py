import json
from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_GET
from django.utils import timezone

from .models import AccessRequest


@login_required
@require_GET
def poll_updates(request):
    """
    Lightweight polling endpoint that returns JSON with real-time status updates.
    The client polls this every few seconds to update the UI without page refresh.
    """
    user = request.user
    now = timezone.now()

    # Active sessions for the current user
    active_requests = AccessRequest.objects.filter(
        requester=user,
        status__in=[AccessRequest.Status.PROVISIONED, AccessRequest.Status.ACTIVE],
    )
    active_sessions = [
        {
            'id': r.id,
            'role': r.role.name,
            'provider': r.role.provider,
            'expires_at': r.expires_at.isoformat() if r.expires_at else None,
            'expires_in_seconds': int((r.expires_at - now).total_seconds()) if r.expires_at and r.expires_at > now else 0,
            'status': r.status,
            'status_display': r.get_status_display(),
        }
        for r in active_requests
    ]

    # Recent requests for the current user (last 10)
    recent_requests = AccessRequest.objects.filter(requester=user)[:10]
    recent = [
        {
            'id': r.id,
            'role': r.role.name,
            'status': r.status,
            'status_display': r.get_status_display(),
            'created_at': r.created_at.isoformat(),
        }
        for r in recent_requests
    ]

    # Pending approvals count (for approvers)
    pending_count = 0
    if user.is_approver:
        pending_count = AccessRequest.objects.filter(
            role__approvers=user,
            status=AccessRequest.Status.PENDING,
        ).count()

    # Pending approvals list (for approvers)
    pending_approvals = []
    if user.is_approver:
        pending_qs = AccessRequest.objects.filter(
            role__approvers=user,
            status=AccessRequest.Status.PENDING,
        )[:10]
        pending_approvals = [
            {
                'id': r.id,
                'requester': r.requester.get_full_name() or r.requester.username,
                'role': r.role.name,
                'duration': r.requested_duration_minutes,
                'created_at': r.created_at.isoformat(),
            }
            for r in pending_qs
        ]

    return JsonResponse({
        'active_sessions': active_sessions,
        'active_count': len(active_sessions),
        'recent_requests': recent,
        'pending_count': pending_count,
        'pending_approvals': pending_approvals,
        'server_time': now.isoformat(),
    })
