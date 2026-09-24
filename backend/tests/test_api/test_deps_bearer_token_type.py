"""Only an access token authenticates a bearer request: every other token the server signs names a
user too, but none carries the enforced-2FA scope an access token is minted with."""

from datetime import datetime, timedelta, timezone

import pytest
from fastapi import HTTPException
from jose import jwt
from prometheus_client import REGISTRY

from app.api.deps import get_current_user
from app.core import security
from app.core.config import settings
from app.core.permissions import Permissions
from tests.mocks.fake_mongo import FakeDatabase

# Reset and verification tokens name an email, so an account whose username is its email is the
# one they would open.
_USERNAME = "bob@test.com"
_STORED_PERMISSIONS = [Permissions.SYSTEM_MANAGE]
_UNAUTHORIZED = 401
_MSG_CREDENTIALS = "Could not validate credentials"
# Stored datetimes come back naive and .timestamp() reads them in the process timezone, so the
# logout lies far enough ahead to stay ahead of any offset.
_LOGOUT_AFTER_ISSUE = timedelta(days=1)


def _untyped_token(subject: str) -> str:
    return jwt.encode({"sub": subject, "permissions": []}, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def _validations(result: str) -> float:
    return REGISTRY.get_sample_value("auth_token_validations_total", {"result": result}) or 0.0


async def _db_with_user(**fields) -> FakeDatabase:
    db = FakeDatabase()
    await db.users.insert_one(
        {
            "_id": "u-1",
            "username": _USERNAME,
            "email": _USERNAME,
            "is_active": True,
            "permissions": list(_STORED_PERMISSIONS),
            **fields,
        }
    )
    return db


@pytest.mark.parametrize(
    "mint",
    [
        pytest.param(security.create_refresh_token, id="refresh"),
        pytest.param(security.create_password_reset_token, id="password-reset"),
        pytest.param(security.create_email_verification_token, id="email-verification"),
        pytest.param(_untyped_token, id="no-type-claim"),
    ],
)
@pytest.mark.asyncio
async def test_a_token_of_another_type_is_refused_as_bearer_and_counted_invalid(mint):
    db = await _db_with_user()
    invalid_before = _validations("invalid")

    with pytest.raises(HTTPException) as exc_info:
        await get_current_user(db=db, token=mint(_USERNAME))

    assert exc_info.value.status_code == _UNAUTHORIZED
    assert exc_info.value.detail == _MSG_CREDENTIALS
    assert _validations("invalid") == invalid_before + 1


@pytest.mark.asyncio
async def test_an_access_token_is_accepted_as_bearer():
    db = await _db_with_user()
    valid_before = _validations("valid")

    user = await get_current_user(db=db, token=security.create_access_token(_USERNAME))

    assert user.username == _USERNAME
    assert user.permissions == _STORED_PERMISSIONS
    assert _validations("valid") == valid_before + 1


@pytest.mark.asyncio
async def test_an_access_token_issued_before_the_last_logout_is_refused():
    db = await _db_with_user(last_logout_at=datetime.now(timezone.utc) + _LOGOUT_AFTER_ISSUE)
    revoked_before = _validations("revoked")

    with pytest.raises(HTTPException) as exc_info:
        await get_current_user(db=db, token=security.create_access_token(_USERNAME))

    assert exc_info.value.status_code == _UNAUTHORIZED
    assert _validations("revoked") == revoked_before + 1
