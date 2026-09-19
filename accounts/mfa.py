"""Elevation-time MFA helpers: TOTP verification, challenge tickets, lockout.

The challenge flow uses an HMAC-signed ticket stored in the session (plus the
user's form data re-submitted as hidden inputs), so no sensitive form data is
stashed server-side and each ticket is single-use. Lockout is session-based:
5 consecutive failures lock the browser session for 15 minutes.
"""

import logging
import re
import secrets
import time

import pyotp
from django.conf import settings
from django.core import signing

logger = logging.getLogger(__name__)

SESSION_TICKET_KEY = 'mfa_ticket'
SESSION_FAILED_KEY = 'mfa_failed_attempts'
SESSION_LOCKED_KEY = 'mfa_locked_until'

VALID_ACTIONS = ('create_request', 'approve_request', 'break_glass', 'reveal_vault_secret')


def normalize_code(code) -> str:
    """Strip everything but digits (accepts '123 456', '123-456', ...)."""
    return re.sub(r'\D', '', str(code or ''))


def verify_totp(user, code) -> bool:
    """Verify a 6-digit TOTP code against the user's stored secret."""
    secret = user.get_otp_secret()
    code = normalize_code(code)
    if not secret or not code:
        return False
    try:
        return pyotp.TOTP(secret).verify(code, valid_window=1)
    except Exception:
        logger.exception('TOTP verification failed for user %s', user.pk)
        return False


def issue_mfa_ticket(request, action, target_id) -> str:
    """Create a signed, expiring challenge ticket and store it in the session.

    Returns the ticket string to render as a hidden input on the challenge
    page. The session copy is popped only after a successful challenge,
    making the ticket single-use.
    """
    if action not in VALID_ACTIONS:
        raise ValueError(f'Unknown MFA challenge action: {action}')
    ticket = signing.dumps(
        {
            'action': action,
            'user_id': str(request.user.pk),
            'target_id': str(target_id),
        },
        salt='pam.mfa_ticket',
    )
    request.session[SESSION_TICKET_KEY] = ticket
    return ticket


def consume_mfa_ticket(request, submitted, expected_target_id):
    """Validate a submitted challenge ticket against the session copy.

    Returns (payload, None) when valid, or (None, error_message) otherwise.
    Does not pop the session ticket on failure, so a stale ticket can be
    reported without destroying a newer one (two-tab race). The caller pops
    the session ticket only on success.
    """
    if not submitted:
        return None, 'Missing challenge ticket.'
    session_ticket = request.session.get(SESSION_TICKET_KEY, '')
    if not session_ticket or not secrets.compare_digest(str(submitted), session_ticket):
        return None, 'Your challenge ticket is stale. Please retry the action from its original page.'
    try:
        payload = signing.loads(submitted, salt='pam.mfa_ticket', max_age=settings.PAM_MFA_TICKET_TTL)
    except signing.SignatureExpired:
        return None, 'Your challenge expired. Please retry the action.'
    except signing.BadSignature:
        return None, 'Invalid challenge ticket.'
    if payload.get('user_id') != str(request.user.pk):
        return None, 'Challenge ticket does not belong to the current user.'
    if payload.get('action') not in VALID_ACTIONS:
        return None, 'Invalid challenge action.'
    if payload.get('target_id') != str(expected_target_id):
        return None, 'Challenge ticket does not match the requested action.'
    return payload, None


# ── Session-based lockout ──────────────────────────────────────────────────

def mfa_is_locked(request) -> bool:
    """True while the session is locked out from MFA challenges."""
    locked_until = request.session.get(SESSION_LOCKED_KEY)
    if not locked_until:
        return False
    if time.time() < float(locked_until):
        return True
    # Lock expired - reset counters for a fresh start
    request.session.pop(SESSION_LOCKED_KEY, None)
    request.session.pop(SESSION_FAILED_KEY, None)
    return False


def mfa_lockout_remaining(request) -> int:
    """Seconds remaining in the lockout, 0 if not locked."""
    locked_until = request.session.get(SESSION_LOCKED_KEY)
    if not locked_until:
        return 0
    return max(0, int(float(locked_until) - time.time()))


def mfa_record_failure(request) -> bool:
    """Increment the failure counter; returns True when the session is now locked."""
    attempts = int(request.session.get(SESSION_FAILED_KEY, 0)) + 1
    if attempts >= settings.PAM_MFA_MAX_ATTEMPTS:
        request.session[SESSION_LOCKED_KEY] = time.time() + settings.PAM_MFA_LOCKOUT_MINUTES * 60
        request.session[SESSION_FAILED_KEY] = 0
        return True
    request.session[SESSION_FAILED_KEY] = attempts
    return False


def mfa_clear_failures(request):
    request.session.pop(SESSION_FAILED_KEY, None)
    request.session.pop(SESSION_LOCKED_KEY, None)
