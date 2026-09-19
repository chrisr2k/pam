"""Vault action executors (mirror the access_requests/services.py pattern)."""

import logging

from cryptography.fernet import InvalidToken
from django.utils import timezone

from access_requests.models import AccessRequest
from audit.middleware import log_action
from .models import VaultEntry

logger = logging.getLogger(__name__)


def active_checkout_for(user, entry_id):
    """The user's active (non-expired) checkout request for an entry, or None."""
    return AccessRequest.objects.filter(
        requester=user,
        role__provider='VAULT',
        role__vault_entry_id=entry_id,
        status__in=[AccessRequest.Status.PROVISIONED, AccessRequest.Status.ACTIVE],
        expires_at__gt=timezone.now(),
    ).order_by('-created_at').first()


def execute_reveal(user, entry_id, request=None):
    """Reveal a vault secret for a user with an active checkout.

    Returns (secret, None) on success or (None, error_message). Re-validates
    everything at execution time; audit details never contain the secret.
    """
    entry = VaultEntry.objects.filter(pk=entry_id, is_active=True).first()
    if entry is None:
        return None, 'Vault entry is unavailable.'

    checkout = active_checkout_for(user, entry_id)
    if checkout is None:
        return None, 'You have no active checkout for this entry.'

    try:
        secret = entry.get_secret_value()
    except InvalidToken:
        logger.error(f'Failed to decrypt vault entry {entry.pk} ({entry.name})')
        return None, 'Vault entry cannot be decrypted (was SECRET_KEY rotated?).'

    log_action(
        actor=user,
        action='VAULT_SECRET_REVEALED',
        target_type='VaultEntry',
        target_id=entry.pk,
        details={
            'entry': entry.name,
            'checkout_request_id': checkout.pk,
        },
        request=request,
    )
    return secret, None
