"""Encryption, rotation-value generation, and reuse hashing for the vault.

Secrets are encrypted at rest with Fernet (AES-128-CBC + HMAC) using a key
derived from settings.SECRET_KEY.

WARNING: rotating SECRET_KEY permanently destroys the ability to decrypt all
stored vault secrets. Export every vault secret before rotating SECRET_KEY;
there is no re-encryption tooling in this version.
"""

import base64
import hashlib
import hmac
import secrets
import string

from cryptography.fernet import Fernet
from django.conf import settings


def _fernet() -> Fernet:
    """Build a Fernet instance from the SECRET_KEY (per call, never cached)."""
    key = base64.urlsafe_b64encode(hashlib.sha256(settings.SECRET_KEY.encode()).digest())
    return Fernet(key)


def encrypt_value(plaintext: str) -> str:
    """Encrypt a plaintext secret value."""
    return _fernet().encrypt(plaintext.encode()).decode()


def decrypt_value(token: str) -> str:
    """Decrypt a stored token back to plaintext.

    Raises cryptography.fernet.InvalidToken on tampering or key mismatch;
    callers are expected to catch it and surface a clear error.
    """
    return _fernet().decrypt(token.encode()).decode()


def generate_rotation_value(exclude: str = '') -> str:
    """Generate a strong random value suitable as a replacement secret.

    24 chars over letters+digits+punctuation, re-rolled until every character
    class (upper, lower, digit, punctuation) appears at least once. `exclude`
    removes characters from the alphabet (e.g. quotes for WinRM command
    lines); excluding an entire class raises ValueError rather than looping
    forever.
    """
    alphabet = string.ascii_letters + string.digits + string.punctuation
    if exclude:
        alphabet = ''.join(c for c in alphabet if c not in exclude)
        for name, present in (
            ('upper', any(c.isupper() for c in alphabet)),
            ('lower', any(c.islower() for c in alphabet)),
            ('digit', any(c.isdigit() for c in alphabet)),
            ('punctuation', any(c in string.punctuation for c in alphabet)),
        ):
            if not present:
                raise ValueError(f'exclude removes the required {name} character class')
    while True:
        value = ''.join(secrets.choice(alphabet) for _ in range(24))
        if (any(c.isupper() for c in value)
                and any(c.islower() for c in value)
                and any(c.isdigit() for c in value)
                and any(c in string.punctuation for c in value)):
            return value


def hash_previous_value(plaintext: str) -> str:
    """Keyed HMAC-SHA256 of a secret value, for reuse detection.

    Keyed (not plain SHA-256) so the hash column cannot be used for offline
    cracking of low-entropy previous secrets without the SECRET_KEY. Enables
    exact reuse detection by comparing keyed hashes.
    """
    key = hashlib.sha256(b'pam.vault.reuse' + settings.SECRET_KEY.encode()).digest()
    return hmac.new(key, plaintext.encode(), hashlib.sha256).hexdigest()
