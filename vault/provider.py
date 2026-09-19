"""VaultProvider: implements the provider interface for vault checkout.

Checkout state lives in the AccessRequest row itself (PROVISIONED/ACTIVE +
expires_at), so provision_access only validates the entry and returns a
self-describing reference id; deprovision_access releases the checkout and
optionally rotates the secret.
"""

import logging

from providers.base import BasePrivilegedAccessProvider
from .models import VaultEntry, VaultRotationEvent
from .rotation import rotate_entry

logger = logging.getLogger(__name__)


class VaultProvider(BasePrivilegedAccessProvider):
    """Backs vault checkout through the standard JIT provisioning machinery."""

    def provision_access(self, user_entra_oid, role_config, duration_minutes):
        entry_id = role_config.get('entry_id')
        if not entry_id:
            return {'success': False, 'error': 'No vault entry ID in role config'}
        entry = VaultEntry.objects.filter(pk=entry_id, is_active=True).first()
        if entry is None:
            return {'success': False, 'error': 'Vault entry not found or inactive'}
        return {
            'success': True,
            'reference_id': f'vault:{entry_id}',
            'status': 'checked_out',
        }

    def deprovision_access(self, reference_id):
        """Release a checkout; rotate the secret if the entry is flagged."""
        try:
            entry_id = int(str(reference_id).split(':', 1)[1])
        except (IndexError, ValueError):
            logger.error(f'Malformed vault reference id: {reference_id}')
            return False

        entry = VaultEntry.objects.filter(pk=entry_id).first()
        if entry is None:
            # Entry deleted while checkout was active: nothing to rotate, and
            # the request should still be marked EXPIRED.
            return True

        if not entry.auto_rotate:
            return True

        ok, error = rotate_entry(entry, VaultRotationEvent.Reason.AUTO_CHECKIN)
        if not ok:
            # A rotation failure must never wedge the deprovision pipeline;
            # the failure event + audit is the record.
            logger.error(
                f'Auto-rotation failed for vault entry {entry.pk} ({entry.name}): {error}')
        return True

    def list_available_roles(self):
        # Vault entries are DB-managed, not provider-discovered
        return []

    def check_access_status(self, reference_id):
        """Entry-based status; checkout liveness lives in AccessRequest rows."""
        try:
            entry_id = int(str(reference_id).split(':', 1)[1])
        except (IndexError, ValueError):
            return 'not_found'
        entry = VaultEntry.objects.filter(pk=entry_id).first()
        if entry is None:
            return 'not_found'
        if not entry.is_active:
            return 'expired'
        return 'active'
