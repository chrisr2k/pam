"""Action executors shared by the direct views and the MFA challenge dispatcher.

Each executor re-validates all authorization state at execution time, so an
action completed via an MFA challenge cannot drift stale (e.g. a request
denied, or an approver removed from a role, while the challenge page was
open). Executors do not touch the messages framework; callers add user-facing
messages before redirecting.
"""

import logging
import threading

from django.conf import settings
from django.contrib.auth import get_user_model
from django.db import IntegrityError, transaction
from django.db.models import Q
from django.utils import timezone

from audit.middleware import log_action
from notifications.services import send_notification
from roles.models import PrivilegedRole
from .forms import AccessRequestForm
from .models import AccessRequest, Approval

logger = logging.getLogger(__name__)

User = get_user_model()


def duration_was_clamped(post_data, access_request) -> bool:
    """True when the submitted duration exceeded the role max and was reduced."""
    try:
        requested = int(post_data.get('requested_duration_minutes') or 0)
    except (TypeError, ValueError):
        return False
    return bool(access_request) and access_request.requested_duration_minutes < requested


def execute_approve(user, access_request_id, comment='', request=None):
    """Approve a pending access request (re-checks all authorization).

    Returns (ok, error, outcome) where outcome is 'approved' (quorum met,
    request finalized), 'vote_recorded' (quorum not yet met), or
    'duplicate_vote' (this approver already voted — handled gracefully,
    never an IntegrityError).

    The read-check-write sequence runs inside a transaction: select_for_update
    requires one on PostgreSQL (sqlite is a no-op), and the row lock must
    cover the whole vote/finalize check to serialize concurrent approvers.
    """
    with transaction.atomic():
        # select_for_update serializes concurrent finalizing votes (no-op on
        # sqlite tests, enforced on the server's Postgres).
        access_request = AccessRequest.objects.select_for_update().filter(
            pk=access_request_id, status=AccessRequest.Status.PENDING).first()
        if access_request is None:
            return False, 'Request is no longer pending approval.', None

        if user == access_request.requester:
            return False, 'You cannot approve your own request.', None

        if user not in access_request.role.approvers.all():
            return False, 'You are not authorized to approve requests for this role.', None

        # One ballot per approver
        if access_request.approvals.filter(approver=user).exists():
            return True, None, 'duplicate_vote'

        try:
            Approval.objects.create(
                request=access_request,
                approver=user,
                decision=Approval.Decision.APPROVED,
                comment=comment or '',
            )
        except IntegrityError:
            # Two-tab race slipped past the exists() check; the unique_together
            # constraint on (request, approver) held.
            return True, None, 'duplicate_vote'

        votes = access_request.approvals.filter(decision=Approval.Decision.APPROVED).count()
        threshold = access_request.role.approval_threshold()

        if votes < threshold:
            # Quorum not yet met: record the vote, leave the request PENDING.
            log_action(
                actor=user,
                action='APPROVAL_RECORDED',
                target_type='AccessRequest',
                target_id=access_request.pk,
                details={
                    'requester': access_request.requester.email,
                    'role': access_request.role.name,
                    'provider': access_request.role.provider,
                    'approval_policy': access_request.role.approval_policy,
                    'votes': votes,
                    'threshold': threshold,
                    'comment': comment or '',
                },
                request=request,
            )
            return True, None, 'vote_recorded'

        access_request.approve(user)
        log_action(
            actor=user,
            action='REQUEST_APPROVED',
            target_type='AccessRequest',
            target_id=access_request.pk,
            details={
                'requester': access_request.requester.email,
                'role': access_request.role.name,
                'provider': access_request.role.provider,
                'approval_policy': access_request.role.approval_policy,
                'votes': votes,
                'threshold': threshold,
            },
            request=request,
        )

    # Outside the transaction: network I/O and the provisioning thread must
    # not run while holding the row lock.
    send_notification(
        access_request,
        'request_approved',
        recipients=[access_request.requester.email],
    )

    # Provision access in the background. We use a thread so the redirect
    # happens immediately and the user sees the detail page with
    # "PROVISIONING" status. The live-updates JS will update the status when
    # provisioning completes.
    from tasks.provisioning import provision_access_sync
    t = threading.Thread(
        target=provision_access_sync,
        args=(access_request.id,),
        daemon=True,
    )
    t.start()
    return True, None, 'approved'


def execute_create(user, post_data, request=None):
    """Create an access request from submitted form data.

    Returns (access_request, None) on success or (None, form) when the data
    fails re-validation at execution time. Roles with requires_approval=False
    are created directly in APPROVED state and provisioned immediately.
    """
    form = AccessRequestForm(post_data)
    if not form.is_valid():
        return None, form
    access_request = form.save(commit=False)
    access_request.requester = user

    role = access_request.role
    auto = not role.requires_approval
    if auto:
        access_request.status = AccessRequest.Status.APPROVED
        access_request.approved_by = user
        access_request.approved_at = timezone.now()
    access_request.save()

    log_action(
        actor=user,
        action='REQUEST_CREATED',
        target_type='AccessRequest',
        target_id=access_request.pk,
        details={
            'role': access_request.role.name,
            'provider': access_request.role.provider,
            'duration': access_request.requested_duration_minutes,
            'auto': auto,
            'approval_policy': role.approval_policy,
        },
        request=request,
    )

    if auto:
        # No approval needed: provision immediately in the background. The
        # provisioning task's 'access_provisioned' notification is the
        # user-facing signal; approvers are not involved.
        from tasks.provisioning import provision_access_sync
        t = threading.Thread(
            target=provision_access_sync,
            args=(access_request.id,),
            daemon=True,
        )
        t.start()
    else:
        # Send notification to approvers
        approver_emails = list(
            access_request.role.approvers.values_list('email', flat=True)
        )
        send_notification(
            access_request,
            'request_created',
            recipients=approver_emails,
        )
    return access_request, None


def execute_break_glass(user, role_id, justification, duration_minutes, request=None):
    """Trigger break-glass emergency access for a flagged role.

    Re-validates the role at execution time and creates the request directly
    in APPROVED state (no approval workflow, no Approval row). Duration is
    clamped to min(role.max_duration_minutes, PAM_BREAK_GLASS_DURATION_MINUTES).
    Alerts all admin/staff users. Returns (access_request, None) or (None, error).
    """
    role = PrivilegedRole.objects.filter(
        pk=role_id, is_active=True, is_break_glass=True).first()
    if role is None:
        return None, 'The selected role is not eligible for break-glass access.'

    try:
        requested = int(duration_minutes or settings.PAM_BREAK_GLASS_DURATION_MINUTES)
    except (TypeError, ValueError):
        requested = settings.PAM_BREAK_GLASS_DURATION_MINUTES
    duration = min(
        max(requested, 1),
        role.max_duration_minutes,
        settings.PAM_BREAK_GLASS_DURATION_MINUTES,
    )

    access_request = AccessRequest.objects.create(
        requester=user,
        role=role,
        justification=justification,
        requested_duration_minutes=duration,
        status=AccessRequest.Status.APPROVED,
        approved_by=user,
        approved_at=timezone.now(),
        is_break_glass=True,
    )
    log_action(
        actor=user,
        action='BREAK_GLASS_TRIGGERED',
        target_type='AccessRequest',
        target_id=access_request.pk,
        details={
            'role': role.name,
            'provider': role.provider,
            'duration_minutes': duration,
            'justification': justification,
        },
        request=request,
    )
    # Loud alert to every admin/staff user (email + Slack/Teams if configured)
    admin_emails = list(
        User.objects.filter(Q(role=User.Role.ADMIN) | Q(is_staff=True))
        .exclude(email='')
        .values_list('email', flat=True)
    )
    send_notification(
        access_request,
        'break_glass_triggered',
        recipients=admin_emails,
    )

    # Provision immediately in the background (same pattern as approval)
    from tasks.provisioning import provision_access_sync
    t = threading.Thread(
        target=provision_access_sync,
        args=(access_request.id,),
        daemon=True,
    )
    t.start()
    return access_request, None
