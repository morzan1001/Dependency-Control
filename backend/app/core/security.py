import hashlib
import logging
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

import jwt
import pyotp
from passlib.context import CryptContext
from pydantic import ValidationError

from app.core.config import settings
from app.core.constants import (
    EMAIL_VERIFICATION_TOKEN_EXPIRE_HOURS,
    PASSWORD_RESET_TOKEN_EXPIRE_HOURS,
    SLACK_OAUTH_STATE_TTL_SECONDS,
    TOTP_VALID_WINDOW,
)
from app.schemas.token import TokenPayload

logger = logging.getLogger(__name__)

pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")


def _create_token(
    subject: str,
    token_type: str,
    expire: datetime,
    extra_claims: dict | None = None,
) -> str:
    """Create a JWT with a jti claim (for blacklisting on logout) and optional extra claims."""
    to_encode = {
        "exp": expire,
        # A float, because a datetime claim is encoded truncated to the second and last_logout_at is finer.
        "iat": time.time(),
        "sub": str(subject),
        "type": token_type,
        "jti": str(uuid.uuid4()),
    }
    if extra_claims:
        to_encode.update(extra_claims)

    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def _decode_typed_token(token: str, expected_type: str) -> dict[str, Any] | None:
    """The claims of a valid JWT of the expected type, or None if invalid."""
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
    except jwt.ExpiredSignatureError:
        logger.debug(f"{expected_type} token expired")
        return None
    except jwt.PyJWTError as e:
        logger.debug(f"{expected_type} token invalid: {e}")
        return None
    if payload.get("type") != expected_type:
        return None
    return payload


def _verify_token(token: str, expected_type: str) -> str | None:
    """Verify a JWT of the expected type, returning its subject (sub claim) or None if invalid."""
    payload = _decode_typed_token(token, expected_type)
    return payload.get("sub") if payload else None


def decode_session_token(token: str, expected_type: str) -> TokenPayload | None:
    """The claims of a valid access or refresh token of the expected type, or None."""
    payload = _decode_typed_token(token, expected_type)
    if payload is None:
        return None
    try:
        return TokenPayload(**payload)
    except ValidationError:
        return None


def create_access_token(subject: str, permissions: list[str] | None = None) -> str:
    return _create_token(
        subject=subject,
        token_type="access",
        expire=datetime.now(timezone.utc) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
        extra_claims={"permissions": permissions or []},
    )


def create_refresh_token(subject: str) -> str:
    """Create a refresh token."""
    expire = datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    return _create_token(subject=subject, token_type="refresh", expire=expire)


def create_token_pair(subject: str, permissions: list[str]) -> tuple[str, str]:
    return create_access_token(subject, permissions), create_refresh_token(subject)


def verify_password(plain_password: str, hashed_password: str | None) -> bool:
    """Verify a plain password against a hashed password."""
    if not hashed_password:
        return False
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    """Hash a password using Argon2."""
    return pwd_context.hash(password)


def verify_totp(secret: str, code: str) -> int | None:
    """The time step ``code`` belongs to within TOTP_VALID_WINDOW, or None."""
    totp = pyotp.TOTP(secret)
    current = totp.timecode(datetime.now(timezone.utc))
    steps = range(current - TOTP_VALID_WINDOW, current + TOTP_VALID_WINDOW + 1)
    return next((step for step in steps if pyotp.utils.strings_equal(code, totp.generate_otp(step))), None)


def create_email_verification_token(email: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(hours=EMAIL_VERIFICATION_TOKEN_EXPIRE_HOURS)
    return _create_token(subject=email, token_type="email_verification", expire=expire)


def verify_email_verification_token(token: str) -> str | None:
    """Verify an email verification token and return the email if valid."""
    return _verify_token(token, "email_verification")


def create_slack_oauth_state(user_id: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(seconds=SLACK_OAUTH_STATE_TTL_SECONDS)
    return _create_token(subject=user_id, token_type="slack_oauth", expire=expire)


def verify_slack_oauth_state(state: str) -> str | None:
    """The id of the user who started a Slack install, if ``state`` is a valid install state."""
    return _verify_token(state, "slack_oauth")


def create_email_change_token(user_id: str, new_email: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(hours=EMAIL_VERIFICATION_TOKEN_EXPIRE_HOURS)
    return _create_token(subject=user_id, token_type="email_change", expire=expire, extra_claims={"email": new_email})


def verify_email_change_token(token: str) -> tuple[str, str] | None:
    """Verify an email change token and return (user_id, new_email) if valid."""
    payload = _decode_typed_token(token, "email_change")
    if not payload or not payload.get("sub") or not payload.get("email"):
        return None
    return payload["sub"], payload["email"]


def password_fingerprint(hashed_password: str | None) -> str:
    """Ties a reset link to the password it replaces, so any password change voids the link."""
    return hashlib.sha256((hashed_password or "").encode()).hexdigest()[:16]


def create_password_reset_token(email: str, hashed_password: str | None) -> str:
    expire = datetime.now(timezone.utc) + timedelta(hours=PASSWORD_RESET_TOKEN_EXPIRE_HOURS)
    return _create_token(
        subject=email,
        token_type="password_reset",
        expire=expire,
        extra_claims={"pwf": password_fingerprint(hashed_password)},
    )


def verify_password_reset_token(token: str) -> tuple[str, str] | None:
    """Verify a password reset token and return (email, password fingerprint) if valid."""
    payload = _decode_typed_token(token, "password_reset")
    if not payload or not payload.get("sub") or not payload.get("pwf"):
        return None
    return payload["sub"], payload["pwf"]
