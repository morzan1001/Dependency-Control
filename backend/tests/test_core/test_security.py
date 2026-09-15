"""Tests for JWT token creation/verification and password hashing."""

from datetime import datetime, timedelta, timezone

import pytest

from app.core.security import (
    create_access_token,
    create_email_verification_token,
    create_password_reset_token,
    create_refresh_token,
    get_password_hash,
    verify_email_verification_token,
    verify_password,
    verify_password_reset_token,
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
    def test_a_caller_supplied_expiry_is_the_one_encoded(self):
        from jose import jwt

        from app.core.config import settings

        delta = timedelta(hours=1)
        before = datetime.now(timezone.utc)

        token = create_access_token("user123", expires_delta=delta)

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
                lambda subject: create_access_token(subject, expires_delta=timedelta(seconds=-1)),
                id="expired-token",
            ),
        ],
    )
    def test_a_token_that_is_not_a_live_verification_token_is_rejected(self, make_token):
        result = verify_email_verification_token(make_token("test@example.com"))
        assert result is None


class TestPasswordResetToken:
    def test_create_and_verify(self):
        token = create_password_reset_token("test@example.com")
        result = verify_password_reset_token(token)
        assert result == "test@example.com"

    @pytest.mark.parametrize(
        "make_token",
        [
            pytest.param(create_access_token, id="access-token"),
            pytest.param(lambda subject: create_password_reset_token(subject)[:-5] + "XXXXX", id="tampered-signature"),
        ],
    )
    def test_a_token_that_is_not_an_intact_reset_token_is_rejected(self, make_token):
        result = verify_password_reset_token(make_token("test@example.com"))
        assert result is None
