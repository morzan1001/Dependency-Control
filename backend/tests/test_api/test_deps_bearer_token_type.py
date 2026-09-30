"""Only an access token authenticates a bearer request: every other token the server signs names a
user too, but none carries the enforced-2FA scope an access token is minted with."""

import asyncio
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

# Every token is minted for the account's id, so only the type check stands between it and the account.
_USER_ID = "u-1"
_USERNAME = "bob"
_STORED_PERMISSIONS = [Permissions.SYSTEM_MANAGE]
_UNAUTHORIZED = 401
_MSG_CREDENTIALS = "Could not validate credentials"
# The logout lies a whole day after the token was issued, so no clock offset can reorder them.
_LOGOUT_AFTER_ISSUE = timedelta(days=1)
# Far enough from both edges of a second that a logout and the next mint share it.
_MID_SECOND = (0.01, 0.9)


def _untyped_token(subject: str) -> str:
    return jwt.encode({"sub": subject, "permissions": []}, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def _validations(result: str) -> float:
    return REGISTRY.get_sample_value("auth_token_validations_total", {"result": result}) or 0.0


async def _db_with_user(**fields) -> FakeDatabase:
    db = FakeDatabase()
    await db.users.insert_one(
        {
            "_id": _USER_ID,
            "username": _USERNAME,
            "email": "bob@test.com",
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
        pytest.param(lambda subject: security.create_password_reset_token(subject, None), id="password-reset"),
        pytest.param(security.create_email_verification_token, id="email-verification"),
        pytest.param(lambda subject: security.create_email_change_token(subject, "new@test.com"), id="email-change"),
        pytest.param(_untyped_token, id="no-type-claim"),
    ],
)
@pytest.mark.asyncio
async def test_a_token_of_another_type_is_refused_as_bearer_and_counted_invalid(mint):
    db = await _db_with_user()
    invalid_before = _validations("invalid")

    with pytest.raises(HTTPException) as exc_info:
        await get_current_user(db=db, token=mint(_USER_ID))

    assert exc_info.value.status_code == _UNAUTHORIZED
    assert exc_info.value.detail == _MSG_CREDENTIALS
    assert _validations("invalid") == invalid_before + 1


@pytest.mark.asyncio
async def test_an_access_token_is_accepted_as_bearer():
    db = await _db_with_user()
    valid_before = _validations("valid")

    user = await get_current_user(db=db, token=security.create_access_token(_USER_ID))

    assert user.username == _USERNAME
    assert user.permissions == _STORED_PERMISSIONS
    assert _validations("valid") == valid_before + 1


@pytest.mark.asyncio
async def test_an_access_token_issued_before_the_last_logout_is_refused():
    db = await _db_with_user(last_logout_at=datetime.now(timezone.utc) + _LOGOUT_AFTER_ISSUE)
    revoked_before = _validations("revoked")

    with pytest.raises(HTTPException) as exc_info:
        await get_current_user(db=db, token=security.create_access_token(_USER_ID))

    assert exc_info.value.status_code == _UNAUTHORIZED
    assert _validations("revoked") == revoked_before + 1


async def _mid_second_now() -> datetime:
    now = datetime.now(timezone.utc)
    fraction = now.microsecond / 1_000_000
    if not _MID_SECOND[0] <= fraction <= _MID_SECOND[1]:
        await asyncio.sleep(1 - fraction + _MID_SECOND[0] * 2)
        now = datetime.now(timezone.utc)
    return now


@pytest.mark.asyncio
async def test_an_access_token_minted_later_in_the_same_second_as_the_logout_is_accepted():
    db = await _db_with_user(last_logout_at=await _mid_second_now())

    user = await get_current_user(db=db, token=security.create_access_token(_USER_ID))

    assert user.id == _USER_ID


@pytest.mark.asyncio
async def test_a_blacklisted_access_token_is_refused_and_counted_blacklisted():
    db = await _db_with_user()
    token = security.create_access_token(_USER_ID)
    await db.token_blacklist.insert_one({"_id": jwt.get_unverified_claims(token)["jti"]})
    blacklisted_before = _validations("blacklisted")

    with pytest.raises(HTTPException) as exc_info:
        await get_current_user(db=db, token=token)

    assert exc_info.value.status_code == _UNAUTHORIZED
    assert exc_info.value.detail == _MSG_CREDENTIALS
    assert _validations("blacklisted") == blacklisted_before + 1


@pytest.mark.asyncio
async def test_an_access_token_keeps_working_after_the_account_is_renamed():
    db = await _db_with_user()
    token = security.create_access_token(_USER_ID)
    await db.users.update_one({"_id": _USER_ID}, {"$set": {"username": "robert"}})

    user = await get_current_user(db=db, token=token)

    assert user.id == _USER_ID
    assert user.username == "robert"


@pytest.mark.asyncio
async def test_an_access_token_naming_a_username_is_refused():
    db = await _db_with_user()
    not_found_before = _validations("user_not_found")

    with pytest.raises(HTTPException) as exc_info:
        await get_current_user(db=db, token=security.create_access_token(_USERNAME))

    assert exc_info.value.status_code == _UNAUTHORIZED
    assert _validations("user_not_found") == not_found_before + 1
