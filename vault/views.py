"""Vault views: entry management (staff) and checkout reveal (all users)."""

import logging

from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin, UserPassesTestMixin
from django.db.models import Count, OuterRef, Subquery
from django.shortcuts import get_object_or_404, redirect
from django.utils import timezone
from django.views import View
from django.views.generic import CreateView, DetailView, ListView

from access_requests.models import AccessRequest
from audit.middleware import log_action
from .forms import VaultEntryForm
from .models import VaultEntry, VaultRotationEvent
from .rotation import rotate_entry
from .services import active_checkout_for, execute_reveal

logger = logging.getLogger(__name__)


class VaultEntryListView(LoginRequiredMixin, UserPassesTestMixin, ListView):
    """Staff overview of vault entries with active checkout counts."""

    model = VaultEntry
    template_name = 'pam/vault_entry_list.html'
    context_object_name = 'entries'

    def test_func(self):
        return self.request.user.is_staff or self.request.user.is_admin_user

    def get_queryset(self):
        active = AccessRequest.objects.filter(
            role__vault_entry_id=OuterRef('pk'),
            status__in=[AccessRequest.Status.PROVISIONED, AccessRequest.Status.ACTIVE],
            expires_at__gt=timezone.now(),
        ).values('pk')
        return VaultEntry.objects.annotate(
            active_checkouts=Subquery(
                active.values('pk').annotate(count=Count('*')).values('count')))


class VaultEntryCreateView(LoginRequiredMixin, UserPassesTestMixin, CreateView):
    """Staff: create a vault entry (encrypted at rest; shim role auto-created)."""

    model = VaultEntry
    form_class = VaultEntryForm
    template_name = 'pam/vault_entry_form.html'

    def test_func(self):
        return self.request.user.is_staff or self.request.user.is_admin_user

    def form_valid(self, form):
        entry = form.save(commit=False)
        entry.created_by = self.request.user
        entry.updated_by = self.request.user
        entry.set_secret_value(form.cleaned_data['value'])
        entry.save()  # post_save signal creates the shim role
        log_action(
            actor=self.request.user,
            action='VAULT_ENTRY_CREATED',
            target_type='VaultEntry',
            target_id=entry.pk,
            details={
                'entry': entry.name,
                'secret_type': entry.secret_type,
                'auto_rotate': entry.auto_rotate,
            },
            request=self.request,
        )
        messages.success(
            self.request,
            f'Vault entry "{entry.name}" created. A role "Vault: {entry.name}" '
            'was created — assign approvers to it in the Django admin.',
        )
        return redirect('vault:list')


class VaultEntryDetailView(LoginRequiredMixin, DetailView):
    """Entry details: checkout status + reveal form; staff see rotation history."""

    model = VaultEntry
    template_name = 'pam/vault_entry_detail.html'
    context_object_name = 'entry'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['checkout'] = active_checkout_for(self.request.user, self.object.pk)
        if self.request.user.is_staff or self.request.user.is_admin_user:
            context['rotation_events'] = self.object.rotation_events.all()
        return context


class VaultRevealView(LoginRequiredMixin, View):
    """POST: reveal the secret (requires an active checkout; MFA if enrolled)."""

    def post(self, request, pk):
        entry = get_object_or_404(VaultEntry, pk=pk, is_active=True)

        # Pre-check an active checkout before issuing any MFA challenge
        if active_checkout_for(request.user, entry.pk) is None:
            messages.error(request, 'You have no active checkout for this entry.')
            return redirect('vault:detail', pk=entry.pk)

        if request.user.mfa_enrolled:
            from accounts.mfa import issue_mfa_ticket
            from accounts.views import render_mfa_challenge
            issue_mfa_ticket(request, 'reveal_vault_secret', entry.pk)
            return render_mfa_challenge(
                request,
                f'Reveal secret for {entry.name}',
                entry.pk,
                request.POST,
            )

        secret, err = execute_reveal(request.user, entry.pk, request=request)
        if err:
            messages.error(request, err)
            return redirect('vault:detail', pk=entry.pk)
        messages.success(
            request,
            f'Secret for {entry.name}: {secret} — copy it now; it is shown only once.',
        )
        return redirect('vault:detail', pk=entry.pk)


class VaultRotateView(LoginRequiredMixin, UserPassesTestMixin, View):
    """POST (staff): manually rotate an entry's secret value."""

    def test_func(self):
        return self.request.user.is_staff or self.request.user.is_admin_user

    def post(self, request, pk):
        entry = get_object_or_404(VaultEntry, pk=pk)
        if entry.rotation_plugin:
            # Plugin-driven: the posted value (if any) is IGNORED — the plugin
            # generates the new credential and pushes it to the target system.
            ok, error = rotate_entry(
                entry, VaultRotationEvent.Reason.MANUAL,
                user=request.user, request=request)
            if ok:
                messages.success(
                    request,
                    f'Secret for {entry.name} rotated and synced to the target system.')
            else:
                messages.error(
                    request,
                    f'Rotation failed: {error} The existing value was kept.')
        else:
            new_value = request.POST.get('new_value', '')
            if not new_value:
                messages.error(request, 'A new secret value is required.')
                return redirect('vault:detail', pk=entry.pk)
            ok, error = rotate_entry(
                entry, VaultRotationEvent.Reason.MANUAL,
                user=request.user, explicit_value=new_value, request=request)
            if ok:
                messages.success(request, f'Secret for {entry.name} rotated successfully.')
            else:
                messages.error(request, error)
        return redirect('vault:detail', pk=entry.pk)
