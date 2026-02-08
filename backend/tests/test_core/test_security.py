"""Tests for JWT token creation/verification and password hashing."""

from datetime import timedelta

from app.core.security import (
    create_access_token,
    create_refresh_token,
    create_email_verification_token,
    create_password_reset_token,
    verify_email_verification_token,
    verify_password_reset_token,
    verify_password,
    get_password_hash,
)


class TestPasswordHashing:
    def test_hash_and_verify(self):
        hashed = get_password_hash("password123")
        assert verify_password("password123", hashed) is True

    def test_verify_wrong_password(self):
        hashed = get_password_hash("password123")
        assert verify_password("wrong_password", hashed) is False

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
    def test_create_returns_string(self):
        token = create_access_token("user123")
        assert isinstance(token, str)
        assert len(token) > 0

    def test_create_with_custom_expiry(self):
        token = create_access_token("user123", expires_delta=timedelta(hours=1))
        assert isinstance(token, str)

    def test_decode_contains_subject(self):
        from jose import jwt
        from app.core.config import settings

        token = create_access_token("user123")
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        assert payload["sub"] == "user123"

    def test_decode_contains_type(self):
        from jose import jwt
        from app.core.config import settings

        token = create_access_token("user123")
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        assert payload["type"] == "access"

    def test_decode_contains_jti(self):
        from jose import jwt
        from app.core.config import settings

        token = create_access_token("user123")
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        assert "jti" in payload

    def test_decode_contains_permissions(self):
        from jose import jwt
        from app.core.config import settings

        token = create_access_token("user123", permissions=["user:read"])
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        assert payload["permissions"] == ["user:read"]


class TestRefreshToken:
    def test_create_returns_string(self):
        token = create_refresh_token("user123")
        assert isinstance(token, str)

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

    def test_wrong_type_token_rejected(self):
        token = create_access_token("test@example.com")
        result = verify_email_verification_token(token)
        assert result is None

    def test_refresh_token_rejected(self):
        token = create_refresh_token("test@example.com")
        result = verify_email_verification_token(token)
        assert result is None

    def test_expired_returns_none(self):
        token = create_access_token("test@example.com", expires_delta=timedelta(seconds=-1))
        result = verify_email_verification_token(token)
        assert result is None


class TestPasswordResetToken:
    def test_create_and_verify(self):
        token = create_password_reset_token("test@example.com")
        result = verify_password_reset_token(token)
        assert result == "test@example.com"

    def test_wrong_type_token_rejected(self):
        token = create_access_token("test@example.com")
        result = verify_password_reset_token(token)
        assert result is None

    def test_tampered_token_returns_none(self):
        token = create_password_reset_token("test@example.com")
        tampered = token[:-5] + "XXXXX"
        result = verify_password_reset_token(tampered)
        assert result is None
