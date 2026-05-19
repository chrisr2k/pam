import logging
from django.contrib.auth.mixins import LoginRequiredMixin, UserPassesTestMixin
from django.shortcuts import redirect, get_object_or_404
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
            ) if user.is_approver else AccessRequest.objects.none(),
            'available_roles': PrivilegedRole.objects.filter(is_active=True),
        }
        return render(request, 'pam/dashboard.html', context)


class RequestCreateView(LoginRequiredMixin, CreateView):
    """Create a new access request."""
    model = AccessRequest
    template_name = 'pam/request_form.html'
    fields = ['role', 'justification', 'requested_duration_minutes']

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
        form.instance.requester = self.request.user
        response = super().form_valid(form)
        log_action(
            actor=self.request.user,
            action='REQUEST_CREATED',
            target_type='AccessRequest',
            target_id=self.object.pk,
            details={
                'role': self.object.role.name,
                'provider': self.object.role.provider,
                'duration': self.object.requested_duration_minutes,
            },
            request=self.request,
        )
        # Send notification to approvers
        approver_emails = list(
            self.object.role.approvers.values_list('email', flat=True)
        )
        send_notification(
            self.object,
            'request_created',
            recipients=approver_emails,
        )
        messages.success(self.request, 'Access request submitted successfully.')
        return response

    def get_success_url(self):
        return reverse('requests:detail', kwargs={'pk': self.object.pk})


class RequestDetailView(LoginRequiredMixin, DetailView):
    """View details of an access request."""
    model = AccessRequest
    template_name = 'pam/request_detail.html'
    context_object_name = 'request_obj'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['approvals'] = self.object.approvals.all()
        return context


class ApproveRequestView(LoginRequiredMixin, UserPassesTestMixin, View):
    """Approve a pending access request."""

    def test_func(self):
        return self.request.user.is_approver

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

        # Record approval
        Approval.objects.create(
            request=access_request,
            approver=request.user,
            decision=Approval.Decision.APPROVED,
            comment=request.POST.get('comment', ''),
        )

        access_request.approve(request.user)
        log_action(
            actor=request.user,
            action='REQUEST_APPROVED',
            target_type='AccessRequest',
            target_id=access_request.pk,
            details={
                'requester': access_request.requester.email,
                'role': access_request.role.name,
                'provider': access_request.role.provider,
            },
            request=request,
        )
        messages.success(request, f'Request #{access_request.id} approved.')

        # Send notification to requester
        send_notification(
            access_request,
            'request_approved',
            recipients=[access_request.requester.email],
        )

        # Provision synchronously (Celery will be used when broker is available)
        from tasks.provisioning import provision_access_sync
        provision_access_sync(access_request.id)

        return redirect('requests:detail', pk=access_request.pk)



class DenyRequestView(LoginRequiredMixin, UserPassesTestMixin, View):
    """Deny a pending access request."""

    def test_func(self):
        return self.request.user.is_approver

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


class PendingApprovalsView(LoginRequiredMixin, UserPassesTestMixin, ListView):
    """List all pending approvals for the current user."""

    def test_func(self):
        return self.request.user.is_approver

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
        deprovision_access_sync(access_request.id)

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
        deprovision_access_sync(access_request.id)

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


# Import render at the bottom to avoid circular imports
from django.shortcuts import render
