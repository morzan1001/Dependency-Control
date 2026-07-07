import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from jose import ExpiredSignatureError, JWTError, jwt
from passlib.context import CryptContext

from app.core.config import settings
from app.core.constants import (
    EMAIL_VERIFICATION_TOKEN_EXPIRE_HOURS,
    PASSWORD_RESET_TOKEN_EXPIRE_HOURS,
)

logger = logging.getLogger(__name__)

pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")


def _create_token(
    subject: str,
    token_type: str,
    expire: datetime,
    extra_claims: Optional[dict] = None,
) -> str:
    """Create a JWT with a jti claim (for blacklisting on logout) and optional extra claims."""
    import uuid

    to_encode = {
        "exp": expire,
        "iat": datetime.now(timezone.utc),
        "sub": str(subject),
        "type": token_type,
        "jti": str(uuid.uuid4()),
    }
    if extra_claims:
        to_encode.update(extra_claims)

    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def _verify_token(token: str, expected_type: str) -> Optional[str]:
    """Verify a JWT of the expected type, returning its subject (sub claim) or None if invalid."""
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        if payload.get("type") != expected_type:
            return None
        return payload.get("sub")
    except ExpiredSignatureError:
        logger.debug(f"{expected_type} token expired")
        return None
    except JWTError as e:
        logger.debug(f"{expected_type} token invalid: {e}")
        return None


def create_access_token(
    subject: str | Any,
    permissions: Optional[list[str]] = None,
    expires_delta: Optional[timedelta] = None,
) -> str:
    """Create an access token with permissions."""
    if permissions is None:
        permissions = []

    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)

    return _create_token(
        subject=str(subject),
        token_type="access",
        expire=expire,
        extra_claims={"permissions": permissions},
    )


def create_refresh_token(subject: str | Any, expires_delta: Optional[timedelta] = None) -> str:
    """Create a refresh token."""
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)

    return _create_token(subject=str(subject), token_type="refresh", expire=expire)


def verify_password(plain_password: str, hashed_password: Optional[str]) -> bool:
    """Verify a plain password against a hashed password."""
    if not hashed_password:
        return False
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    """Hash a password using Argon2."""
    return pwd_context.hash(password)


def create_email_verification_token(email: str) -> str:
    """Create an email verification token (valid for 24 hours)."""
    expire = datetime.now(timezone.utc) + timedelta(hours=EMAIL_VERIFICATION_TOKEN_EXPIRE_HOURS)
    return _create_token(subject=email, token_type="email_verification", expire=expire)


def verify_email_verification_token(token: str) -> Optional[str]:
    """Verify an email verification token and return the email if valid."""
    return _verify_token(token, "email_verification")


def create_password_reset_token(email: str) -> str:
    """Create a password reset token (valid for 1 hour)."""
    expire = datetime.now(timezone.utc) + timedelta(hours=PASSWORD_RESET_TOKEN_EXPIRE_HOURS)
    return _create_token(subject=email, token_type="password_reset", expire=expire)


def verify_password_reset_token(token: str) -> Optional[str]:
    """Verify a password reset token and return the email if valid."""
    return _verify_token(token, "password_reset")
