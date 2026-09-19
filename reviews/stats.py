"""Role-mining helpers: entitlement usage statistics over grant history.

Read-only query helpers feeding the role detail page and review campaigns.
A "grant" is any request that materialized: PROVISIONED/ACTIVE/EXPIRED/
REVOKED. PENDING/APPROVED/PROVISIONING never materialized; DENIED/FAILED
are noise.
"""

from datetime import timedelta

from django.db.models import Max
from django.utils import timezone

from access_requests.models import AccessRequest

GRANT_STATUSES = (
    AccessRequest.Status.PROVISIONED,
    AccessRequest.Status.ACTIVE,
    AccessRequest.Status.EXPIRED,
    AccessRequest.Status.REVOKED,
)
CURRENT_STATUSES = (
    AccessRequest.Status.PROVISIONED,
    AccessRequest.Status.ACTIVE,
)


def _usage_dict(base_qs, days):
    since = timezone.now() - timedelta(days=days)
    return {
        'request_count': base_qs.filter(created_at__gte=since).count(),
        'distinct_users': base_qs.filter(created_at__gte=since)
                                .values('requester').distinct().count(),
        'last_request_at': base_qs.aggregate(Max('created_at'))['created_at__max'],
        'active_now': base_qs.filter(
            status__in=CURRENT_STATUSES,
            expires_at__gt=timezone.now(),
        ).values('requester').distinct().count(),
    }


def role_usage_stats(role, days=90):
    """Aggregate usage for a role over the last `days` days."""
    base = AccessRequest.objects.filter(role=role, status__in=GRANT_STATUSES)
    return _usage_dict(base, days)


def user_role_stats(user, role, days=90):
    """Usage of one role by one user; active_now is a boolean."""
    base = AccessRequest.objects.filter(
        requester=user, role=role, status__in=GRANT_STATUSES)
    stats = _usage_dict(base, days)
    stats['active_now'] = bool(stats['active_now'])
    return stats


def latest_grant_anchors(grants_qs):
    """Latest grant per distinct (requester, role) pair, as AccessRequest rows.

    ReviewEntry requires an FK to a concrete AccessRequest, so campaigns are
    anchored on the most recent grant evidence for each pair.
    """
    anchors = []
    for pair in grants_qs.values('requester_id', 'role_id').distinct():
        anchor = grants_qs.filter(
            requester_id=pair['requester_id'], role_id=pair['role_id'],
        ).order_by('-created_at').first()
        if anchor is not None:
            anchors.append(anchor)
    return anchors


def unused_entitlements(days=90):
    """Anchor rows for (requester, role) pairs whose latest grant is older
    than `days`, excluding break-glass grants and pairs that currently hold
    an active grant."""
    grants = AccessRequest.objects.filter(
        status__in=GRANT_STATUSES, is_break_glass=False)
    cutoff = timezone.now() - timedelta(days=days)

    stale_pairs = (
        grants.values('requester_id', 'role_id')
        .annotate(last=Max('created_at'))
        .filter(last__lt=cutoff)
    )
    current_pairs = set(
        (r['requester_id'], r['role_id'])
        for r in grants.filter(
            status__in=CURRENT_STATUSES, expires_at__gt=timezone.now(),
        ).values('requester_id', 'role_id')
    )
    anchors = []
    for pair in stale_pairs:
        key = (pair['requester_id'], pair['role_id'])
        if key in current_pairs:
            continue
        anchor = grants.filter(
            requester_id=pair['requester_id'], role_id=pair['role_id'],
        ).order_by('-created_at').first()
        if anchor is not None:
            anchors.append(anchor)
    return anchors
