import logging
from django.conf import settings
from django.contrib.auth.mixins import LoginRequiredMixin, UserPassesTestMixin
from django.shortcuts import redirect, get_object_or_404, render
from django.urls import reverse
from django.views import View
from django.views.generic import ListView, DetailView, CreateView
from django.contrib import messages
from django.utils import timezone

from .models import AccessRequest, Approval
from roles.models import PrivilegedRole
from tasks.provisioning import provision_access, deprovision_access
from audit.middleware import log_action
from notifications.services import send_notification
from .forms import AccessRequestForm
from .services import duration_was_clamped, execute_approve, execute_create

logger = logging.getLogger(__name__)


class DashboardView(LoginRequiredMixin, View):
    """Main dashboard showing active sessions and pending items."""

    def get(self, request):
        user = request.user
        context = {
            'active_requests': AccessRequest.objects.filter(
                requester=user,
                status__in=[AccessRequest.Status.PROVISIONED, AccessRequest.Status.ACTIVE],
            ),
            'recent_requests': AccessRequest.objects.filter(requester=user)[:10],
            'pending_approvals': AccessRequest.objects.filter(
                role__approvers=user,
                status=AccessRequest.Status.PENDING,
            ),
            'available_roles': PrivilegedRole.objects.filter(is_active=True),
        }
        return render(request, 'pam/dashboard.html', context)


class RequestCreateView(LoginRequiredMixin, CreateView):
    """Create a new access request (MFA-challenged when the user is enrolled)."""
    model = AccessRequest
    form_class = AccessRequestForm
    template_name = 'pam/request_form.html'

    def get_initial(self):
        """Pre-select role if ?role= query param is provided."""
        initial = super().get_initial()
        role_id = self.request.GET.get('role')
        if role_id:
            try:
                role = PrivilegedRole.objects.get(pk=role_id, is_active=True)
                initial['role'] = role
            except (PrivilegedRole.DoesNotExist, ValueError):
                pass
        return initial

    def get_form(self, form_class=None):
        form = super().get_form(form_class)
        form.fields['role'].queryset = PrivilegedRole.objects.filter(is_active=True)
        return form

    def form_valid(self, form):
        if self.request.user.mfa_enrolled:
            # Require a TOTP challenge before the request is created. The form
            # data is re-submitted as hidden inputs from the challenge page and
            # re-validated by execute_create at execution time.
            from accounts.mfa import issue_mfa_ticket
            from accounts.views import render_mfa_challenge
            issue_mfa_ticket(self.request, 'create_request', '')
            return render_mfa_challenge(
                self.request,
                f'Submit access request for {form.cleaned_data["role"].name}',
                '',
                self.request.POST,
            )
        access_request, _ = execute_create(
            self.request.user, self.request.POST, request=self.request)
        # The form was already validated by the view, so this cannot be None
        if duration_was_clamped(self.request.POST, access_request):
            messages.warning(
                self.request,
                f'Requested duration exceeds the '
                f'{access_request.role.max_duration_minutes}-minute maximum '
                f'for this role and was reduced.',
            )
        if access_request.status == AccessRequest.Status.APPROVED:
            messages.success(
                self.request,
                'Access granted automatically — this role does not require approval.',
            )
        else:
            messages.success(self.request, 'Access request submitted successfully.')
        return redirect('requests:detail', pk=access_request.pk)


class RequestDetailView(LoginRequiredMixin, DetailView):
    """View details of an access request."""
    model = AccessRequest
    template_name = 'pam/request_detail.html'
    context_object_name = 'request_obj'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['approvals'] = self.object.approvals.all()
        context['user_approval'] = self.object.approvals.filter(
            approver=self.request.user).first()
        context['approval_votes'] = self.object.approvals.filter(
            decision=Approval.Decision.APPROVED).count()
        context['approval_threshold'] = self.object.role.approval_threshold()
        context['approver_count'] = self.object.role.approvers.count()
        return context


class ApproveRequestView(LoginRequiredMixin, View):
    """Approve a pending access request (MFA-challenged when enrolled).

    Authorization is per-role membership (checked in post); being listed as
    an approver of the role is what grants approval, regardless of PAM role.
    """

    def post(self, request, pk):
        access_request = get_object_or_404(AccessRequest, pk=pk, status=AccessRequest.Status.PENDING)

        # Prevent self-approval
        if request.user == access_request.requester:
            messages.error(request, 'You cannot approve your own request.')
            return redirect('requests:detail', pk=access_request.pk)

        # Verify the user is an approver for this specific role
        if request.user not in access_request.role.approvers.all():
            messages.error(request, 'You are not authorized to approve requests for this role.')
            return redirect('requests:detail', pk=access_request.pk)

        # One ballot per approver: don't issue a pointless MFA challenge
        if access_request.approvals.filter(approver=request.user).exists():
            messages.info(request, 'You have already approved this request.')
            return redirect('requests:detail', pk=access_request.pk)

        # MFA gate: approvers/admins must be enrolled before approving; when
        # enrolled, the approval is recorded only after a TOTP challenge.
        if request.user.mfa_required and not request.user.mfa_enrolled:
            messages.error(request, 'MFA enrollment is required before you can approve requests.')
            return redirect('accounts:mfa_setup')
        if request.user.mfa_enrolled:
            from accounts.mfa import issue_mfa_ticket
            from accounts.views import render_mfa_challenge
            issue_mfa_ticket(request, 'approve_request', access_request.pk)
            return render_mfa_challenge(
                request,
                f'Approve request #{access_request.pk} for {access_request.role.name}',
                access_request.pk,
                request.POST,
            )

        ok, err, outcome = execute_approve(
            request.user,
            access_request.pk,
            comment=request.POST.get('comment', ''),
            request=request,
        )
        if not ok:
            messages.error(request, err)
            return redirect('requests:detail', pk=access_request.pk)
        if outcome == 'vote_recorded':
            messages.success(
                request,
                'Your approval has been recorded. Additional approvals are '
                'needed before access is granted.',
            )
        elif outcome == 'duplicate_vote':
            messages.info(request, 'You have already approved this request.')
        else:
            messages.success(request, f'Request #{access_request.id} approved.')
        return redirect('requests:detail', pk=access_request.pk)



class DenyRequestView(LoginRequiredMixin, View):
    """Deny a pending access request.

    Authorization is per-role membership (checked in post), like approval.
    """

    def post(self, request, pk):
        access_request = get_object_or_404(AccessRequest, pk=pk, status=AccessRequest.Status.PENDING)

        # Prevent self-denial
        if request.user == access_request.requester:
            messages.error(request, 'You cannot deny your own request.')
            return redirect('requests:detail', pk=access_request.pk)

        # Verify the user is an approver for this specific role
        if request.user not in access_request.role.approvers.all():
            messages.error(request, 'You are not authorized to deny requests for this role.')
            return redirect('requests:detail', pk=access_request.pk)


        reason = request.POST.get('reason', '')
        Approval.objects.create(
            request=access_request,
            approver=request.user,
            decision=Approval.Decision.DENIED,
            comment=reason,
        )

        access_request.deny(request.user, reason)
        log_action(
            actor=request.user,
            action='REQUEST_DENIED',
            target_type='AccessRequest',
            target_id=access_request.pk,
            details={
                'requester': access_request.requester.email,
                'role': access_request.role.name,
                'reason': reason,
            },
            request=request,
        )
        # Send notification to requester
        send_notification(
            access_request,
            'request_denied',
            recipients=[access_request.requester.email],
        )
        messages.warning(request, f'Request #{access_request.id} denied.')
        return redirect('requests:detail', pk=access_request.pk)


class PendingApprovalsView(LoginRequiredMixin, ListView):
    """List all pending approvals for the current user.

    The queryset self-scopes to roles where the user is an approver, so no
    additional PAM-role gate is needed (role approvers may have any PAM role).
    """
    model = AccessRequest
    template_name = 'pam/pending_approvals.html'
    context_object_name = 'requests'

    def get_queryset(self):
        return AccessRequest.objects.filter(
            role__approvers=self.request.user,
            status=AccessRequest.Status.PENDING,
        )


class MyRequestsView(LoginRequiredMixin, ListView):
    """List the current user's access requests."""
    model = AccessRequest
    template_name = 'pam/my_requests.html'
    context_object_name = 'requests'

    def get_queryset(self):
        return AccessRequest.objects.filter(requester=self.request.user)


class ActiveSessionsView(LoginRequiredMixin, UserPassesTestMixin, ListView):
    """Admin overview of all active sessions across all users."""

    def test_func(self):
        return self.request.user.is_admin_user or self.request.user.is_staff

    model = AccessRequest
    template_name = 'pam/active_sessions.html'
    context_object_name = 'sessions'

    def get_queryset(self):
        return AccessRequest.objects.filter(
            status__in=[AccessRequest.Status.PROVISIONED, AccessRequest.Status.ACTIVE],
        ).select_related('requester', 'role').order_by('-provisioned_at')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['total_active'] = self.get_queryset().count()
        context['sessions_by_provider'] = {}
        for session in context['sessions']:
            provider = session.role.provider
            if provider not in context['sessions_by_provider']:
                context['sessions_by_provider'][provider] = 0
            context['sessions_by_provider'][provider] += 1
        return context


class AdminRevokeAccessView(LoginRequiredMixin, UserPassesTestMixin, View):
    """Admin can revoke any active session."""

    def test_func(self):
        return self.request.user.is_admin_user or self.request.user.is_staff

    def post(self, request, pk):
        access_request = get_object_or_404(
            AccessRequest,
            pk=pk,
            status__in=[AccessRequest.Status.PROVISIONED, AccessRequest.Status.ACTIVE],
        )

        from tasks.provisioning import deprovision_access_sync
        # trigger='revoked': the ADMIN_REVOKED row below is the audit event
        deprovision_access_sync(access_request.id, trigger='revoked')

        log_action(
            actor=request.user,
            action='ADMIN_REVOKED',
            target_type='AccessRequest',
            target_id=access_request.pk,
            details={
                'requester': access_request.requester.email,
                'role': access_request.role.name,
                'provider': access_request.role.provider,
                'reason': 'Admin-initiated revocation',
            },
            request=request,
        )
        requester_name = access_request.requester.get_full_name() or access_request.requester.username
        messages.success(
            request,
            f'Access to {access_request.role.name} for {requester_name} has been revoked.'
        )
        return redirect('requests:active_sessions')


class RevokeAccessView(LoginRequiredMixin, View):
    """Revoke (early deprovision) an active/provisioned access request."""

    def post(self, request, pk):
        access_request = get_object_or_404(
            AccessRequest,
            pk=pk,
            requester=request.user,
            status__in=[AccessRequest.Status.PROVISIONED, AccessRequest.Status.ACTIVE],
        )


        from tasks.provisioning import deprovision_access_sync
        # trigger='revoked': the ACCESS_REVOKED row below is the audit event
        deprovision_access_sync(access_request.id, trigger='revoked')

        log_action(
            actor=request.user,
            action='ACCESS_REVOKED',
            target_type='AccessRequest',
            target_id=access_request.pk,
            details={
                'role': access_request.role.name,
                'provider': access_request.role.provider,
                'reason': 'User-initiated early revocation',
            },
            request=request,
        )
        messages.success(request, f'Access to {access_request.role.name} has been revoked.')
        return redirect('requests:dashboard')


class BreakGlassView(LoginRequiredMixin, UserPassesTestMixin, View):
    """Break-glass emergency access: admins trigger a flagged role immediately.

    Skips the approval workflow; MFA challenge is mandatory. Duration is
    clamped to min(role.max_duration_minutes, PAM_BREAK_GLASS_DURATION_MINUTES).
    """

    def test_func(self):
        return self.request.user.is_admin_user or self.request.user.is_staff

    def get(self, request):
        roles = PrivilegedRole.objects.filter(is_active=True, is_break_glass=True)
        return render(request, 'pam/break_glass.html', {
            'roles': roles,
            'default_duration': settings.PAM_BREAK_GLASS_DURATION_MINUTES,
        })

    def post(self, request):
        role = get_object_or_404(
            PrivilegedRole, pk=request.POST.get('role'), is_active=True, is_break_glass=True)

        # MFA is mandatory for break-glass, regardless of enrollment status
        if not request.user.mfa_enrolled:
            messages.error(request, 'You must set up MFA before using break-glass access.')
            return redirect('accounts:mfa_setup')

        from accounts.mfa import issue_mfa_ticket
        from accounts.views import render_mfa_challenge
        issue_mfa_ticket(request, 'break_glass', role.pk)
        return render_mfa_challenge(
            request,
            f'Break glass: {role.name}',
            role.pk,
            request.POST,
        )

