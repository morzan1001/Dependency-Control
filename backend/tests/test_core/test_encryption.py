"""Tests for archive encryption module.

Tests AES-256-GCM encrypt/decrypt and key derivation.
"""

import os
from unittest.mock import patch

import pytest
from cryptography.exceptions import InvalidTag

MODULE = "app.core.encryption"


# ---------------------------------------------------------------------------
# is_encryption_enabled
# ---------------------------------------------------------------------------


class TestIsEncryptionEnabled:
    def test_returns_false_when_key_empty(self):
        from app.core.encryption import is_encryption_enabled

        with patch(f"{MODULE}.settings") as mock_settings:
            mock_settings.ARCHIVE_ENCRYPTION_KEY = ""
            assert is_encryption_enabled() is False

    def test_returns_true_when_key_set(self):
        from app.core.encryption import is_encryption_enabled

        with patch(f"{MODULE}.settings") as mock_settings:
            mock_settings.ARCHIVE_ENCRYPTION_KEY = "some-key"
            assert is_encryption_enabled() is True


# ---------------------------------------------------------------------------
# encrypt / decrypt roundtrip
# ---------------------------------------------------------------------------


class TestEncryptDecrypt:
    def test_roundtrip_with_hex_key(self):
        from app.core.encryption import decrypt, encrypt

        hex_key = "aa" * 32  # 64 hex chars = 32 bytes
        plaintext = b"Hello, archive data!"

        with patch(f"{MODULE}.settings") as mock_settings:
            mock_settings.ARCHIVE_ENCRYPTION_KEY = hex_key
            ciphertext = encrypt(plaintext)
            result = decrypt(ciphertext)

        assert result == plaintext

    def test_roundtrip_with_string_key(self):
        from app.core.encryption import decrypt, encrypt

        string_key = "my-secret-passphrase"
        plaintext = b"Some compressed archive data" * 100

        with patch(f"{MODULE}.settings") as mock_settings:
            mock_settings.ARCHIVE_ENCRYPTION_KEY = string_key
            ciphertext = encrypt(plaintext)
            result = decrypt(ciphertext)

        assert result == plaintext

    def test_decrypt_wrong_key_raises(self):
        from app.core.encryption import decrypt, encrypt

        plaintext = b"secret data"

        with patch(f"{MODULE}.settings") as mock_settings:
            mock_settings.ARCHIVE_ENCRYPTION_KEY = "correct-key"
            ciphertext = encrypt(plaintext)

        with (
            patch(f"{MODULE}.settings") as mock_settings,
            pytest.raises(InvalidTag),
        ):
            mock_settings.ARCHIVE_ENCRYPTION_KEY = "wrong-key"
            decrypt(ciphertext)

    def test_decrypt_truncated_data_raises(self):
        from app.core.encryption import decrypt

        with (
            patch(f"{MODULE}.settings") as mock_settings,
            pytest.raises(ValueError, match="too short"),
        ):
            mock_settings.ARCHIVE_ENCRYPTION_KEY = "some-key"
            decrypt(b"short")

    def test_nonce_uniqueness(self):
        from app.core.encryption import encrypt

        plaintext = b"same data"

        with patch(f"{MODULE}.settings") as mock_settings:
            mock_settings.ARCHIVE_ENCRYPTION_KEY = "test-key"
            ct1 = encrypt(plaintext)
            ct2 = encrypt(plaintext)

        # Same plaintext should produce different ciphertext (different nonces)
        assert ct1 != ct2

    def test_output_format(self):
        from app.core.encryption import NONCE_SIZE, encrypt

        plaintext = b"test data"

        with patch(f"{MODULE}.settings") as mock_settings:
            mock_settings.ARCHIVE_ENCRYPTION_KEY = "test-key"
            result = encrypt(plaintext)

        # Output should be: NONCE (12 bytes) + ciphertext + GCM tag (16 bytes)
        assert len(result) >= NONCE_SIZE + 16
        # Nonce is the first 12 bytes
        nonce = result[:NONCE_SIZE]
        assert len(nonce) == 12

    def test_roundtrip_with_empty_data(self):
        from app.core.encryption import decrypt, encrypt

        with patch(f"{MODULE}.settings") as mock_settings:
            mock_settings.ARCHIVE_ENCRYPTION_KEY = "test-key"
            ciphertext = encrypt(b"")
            result = decrypt(ciphertext)

        assert result == b""
