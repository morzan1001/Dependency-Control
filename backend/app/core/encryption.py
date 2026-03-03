"""
Client-side encryption for archive data.

Uses AES-256-GCM (authenticated encryption with associated data).
Wire format: NONCE (12 bytes) || CIPHERTEXT+TAG (variable)
"""

import hashlib
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.core.config import settings

NONCE_SIZE = 12  # 96-bit nonce (GCM standard)


def is_encryption_enabled() -> bool:
    """Check if archive encryption is configured."""
    return bool(settings.ARCHIVE_ENCRYPTION_KEY)


def _get_key() -> bytes:
    """Derive 32-byte key from configured string (raw hex or arbitrary string)."""
    raw = settings.ARCHIVE_ENCRYPTION_KEY
    # If exactly 64 hex chars → decode as hex (32 bytes)
    if len(raw) == 64:
        try:
            return bytes.fromhex(raw)
        except ValueError:
            pass
    # Otherwise: SHA-256 hash for consistent 32 bytes
    return hashlib.sha256(raw.encode("utf-8")).digest()


def encrypt(plaintext: bytes) -> bytes:
    """Encrypt data with AES-256-GCM. Returns NONCE || CIPHERTEXT+TAG."""
    key = _get_key()
    nonce = os.urandom(NONCE_SIZE)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return nonce + ciphertext


def decrypt(data: bytes) -> bytes:
    """Decrypt NONCE || CIPHERTEXT+TAG with AES-256-GCM."""
    if len(data) < NONCE_SIZE + 16:  # min: nonce + GCM tag
        raise ValueError("Data too short to be AES-256-GCM encrypted")
    key = _get_key()
    nonce = data[:NONCE_SIZE]
    ciphertext = data[NONCE_SIZE:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)
