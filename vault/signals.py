"""Signals that keep each VaultEntry's shim PrivilegedRole in sync."""

import logging

from django.db.models.signals import post_save, pre_delete
from django.dispatch import receiver

from audit.middleware import log_action
from roles.models import PrivilegedRole
from .models import VaultEntry

logger = logging.getLogger(__name__)


@receiver(post_save, sender=VaultEntry)
def sync_shim_role(sender, instance, **kwargs):
    """Create/update the VAULT-provider PrivilegedRole backing this entry.

    Approvers, approval_policy, and quorum_count are managed on the shim via
    the existing role admin and are never touched here.
    """
    if kwargs.get('raw'):
        return
    shim = PrivilegedRole.objects.filter(
        provider='VAULT', vault_entry=instance).first()
    if shim is None:
        shim = PrivilegedRole(provider='VAULT', vault_entry=instance)
    shim.name = f'Vault: {instance.name}'
    shim.description = instance.description
    shim.requires_approval = instance.requires_approval
    shim.max_duration_minutes = instance.max_checkout_minutes
    shim.is_active = instance.is_active
    shim.save()


@receiver(pre_delete, sender=VaultEntry)
def deactivate_shim_on_delete(sender, instance, **kwargs):
    """Deactivate the shim before the FK is nulled.

    The shim survives (vault_entry is SET_NULL) so checkout/approval audit
    history is preserved; deactivated shims disappear from requester-facing
    role lists.
    """
    shim = PrivilegedRole.objects.filter(
        provider='VAULT', vault_entry=instance).first()
    if shim is not None:
        shim.is_active = False
        shim.save()
    log_action(
        actor=None,
        action='VAULT_ENTRY_DELETED',
        target_type='VaultEntry',
        target_id=instance.pk,
        details={'entry': instance.name},
    )
