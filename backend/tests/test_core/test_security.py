"""Tests for JWT token creation/verification and password hashing."""

from datetime import datetime, timedelta, timezone

import pyotp
import pytest

from app.core.constants import TOTP_VALID_WINDOW
from app.core.security import (
    _create_token,
    create_access_token,
    create_email_verification_token,
    create_password_reset_token,
    create_refresh_token,
    get_password_hash,
    password_fingerprint,
    verify_email_verification_token,
    verify_password,
    verify_password_reset_token,
    verify_totp,
)

# JWT exp is a whole-second timestamp, and the token is minted a moment after the test reads the clock.
_EXPIRY_TOLERANCE = timedelta(seconds=5)


class TestPasswordHashing:
    @pytest.mark.parametrize(
        ("candidate", "matches"),
        [
            pytest.param("password123", True, id="correct-password"),
            pytest.param("wrong_password", False, id="wrong-password"),
        ],
    )
    def test_verify_accepts_only_the_hashed_password(self, candidate, matches):
        hashed = get_password_hash("password123")
        assert verify_password(candidate, hashed) is matches

    def test_verify_none_hash_returns_false(self):
        assert verify_password("password", None) is False

    def test_hash_is_argon2_format(self):
        hashed = get_password_hash("test")
        assert hashed.startswith("$argon2")

    def test_different_passwords_different_hashes(self):
        hash1 = get_password_hash("password123")
        hash2 = get_password_hash("password123")
        assert hash1 != hash2  # Different salts


class TestAccessToken:
    def test_an_access_token_lives_the_configured_minutes(self):
        from jose import jwt

        from app.core.config import settings

        delta = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        before = datetime.now(timezone.utc)

        token = create_access_token("user123")

        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        expiry = datetime.fromtimestamp(payload["exp"], tz=timezone.utc)
        assert delta - _EXPIRY_TOLERANCE <= expiry - before <= delta + _EXPIRY_TOLERANCE

    @pytest.mark.parametrize(
        ("token_kwargs", "claim", "expected"),
        [
            pytest.param({}, "sub", "user123", id="subject"),
            pytest.param({}, "type", "access", id="type"),
            pytest.param({"permissions": ["user:read"]}, "permissions", ["user:read"], id="permissions"),
        ],
    )
    def test_the_decoded_payload_carries_the_claim(self, token_kwargs, claim, expected):
        from jose import jwt

        from app.core.config import settings

        token = create_access_token("user123", **token_kwargs)
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        assert payload[claim] == expected

    def test_decode_contains_jti(self):
        from jose import jwt

        from app.core.config import settings

        token = create_access_token("user123")
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        assert "jti" in payload


class TestRefreshToken:
    def test_decode_type_is_refresh(self):
        from jose import jwt

        from app.core.config import settings

        token = create_refresh_token("user123")
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        assert payload["type"] == "refresh"


class TestEmailVerificationToken:
    def test_create_and_verify(self):
        token = create_email_verification_token("test@example.com")
        result = verify_email_verification_token(token)
        assert result == "test@example.com"

    @pytest.mark.parametrize(
        "make_token",
        [
            pytest.param(create_access_token, id="access-token"),
            pytest.param(create_refresh_token, id="refresh-token"),
            pytest.param(
                lambda subject: _create_token(subject, "access", datetime.now(timezone.utc) - timedelta(seconds=1)),
                id="expired-token",
            ),
        ],
    )
    def test_a_token_that_is_not_a_live_verification_token_is_rejected(self, make_token):
        result = verify_email_verification_token(make_token("test@example.com"))
        assert result is None


class TestPasswordResetToken:
    def test_create_and_verify(self):
        token = create_password_reset_token("test@example.com", "$argon2id$hash")
        assert verify_password_reset_token(token) == ("test@example.com", password_fingerprint("$argon2id$hash"))

    @pytest.mark.parametrize(
        "make_token",
        [
            pytest.param(create_access_token, id="access-token"),
            pytest.param(
                lambda subject: create_password_reset_token(subject, None)[:-5] + "XXXXX", id="tampered-signature"
            ),
            pytest.param(
                lambda subject: _create_token(
                    subject, "password_reset", datetime.now(timezone.utc) + timedelta(hours=1)
                ),
                id="no-password-fingerprint",
            ),
        ],
    )
    def test_a_token_that_is_not_an_intact_reset_token_is_rejected(self, make_token):
        result = verify_password_reset_token(make_token("test@example.com"))
        assert result is None


class TestTotp:
    secret = pyotp.random_base32()

    def _step_now(self) -> int:
        return pyotp.TOTP(self.secret).timecode(datetime.now(timezone.utc))

    def test_a_code_resolves_to_the_step_it_was_generated_for(self):
        step = self._step_now()
        assert verify_totp(self.secret, pyotp.TOTP(self.secret).generate_otp(step)) == step

    def test_a_code_outside_the_window_is_refused(self):
        stale = self._step_now() - TOTP_VALID_WINDOW - 2
        assert verify_totp(self.secret, pyotp.TOTP(self.secret).generate_otp(stale)) is None
