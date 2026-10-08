"""Only an access token authenticates a bearer request: every other token the server signs names a
user too, but none carries the enforced-2FA scope an access token is minted with."""

import asyncio
import base64
import json
import time
from datetime import datetime, timedelta, timezone

import jwt
import pytest
from fastapi import HTTPException
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


def _signed_access(key: str | None = settings.SECRET_KEY, algorithm: str = settings.ALGORITHM, **claims) -> str:
    now = time.time()
    base = {"sub": _USER_ID, "type": "access", "jti": "j-1", "iat": now, "exp": int(now) + 600, "permissions": []}
    return jwt.encode({**base, **claims}, key, algorithm=algorithm)


def _expired_access() -> str:
    return security._create_token(_USER_ID, "access", datetime.now(timezone.utc) - timedelta(seconds=1))


def _redated_expired_access() -> str:
    header, payload, signature = _expired_access().split(".")
    claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    claims["exp"] += 3600
    forged = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
    return f"{header}.{forged}.{signature}"


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


@pytest.mark.parametrize(
    "mint",
    [
        pytest.param(_expired_access, id="expired"),
        pytest.param(_redated_expired_access, id="tampered-payload"),
        pytest.param(lambda: _signed_access(key="another-secret-key-of-sufficient-length"), id="foreign-secret"),
        pytest.param(lambda: _signed_access(key=None, algorithm="none"), id="alg-none"),
        pytest.param(lambda: _signed_access(algorithm="HS512"), id="unpinned-algorithm"),
        pytest.param(lambda: "not-a-jwt", id="malformed"),
        pytest.param(lambda: _signed_access(sub=1), id="sub-not-a-string"),
        pytest.param(lambda: _signed_access(iat="yesterday"), id="iat-not-numeric"),
        pytest.param(lambda: _signed_access(nbf="later"), id="nbf-not-numeric"),
        pytest.param(lambda: _signed_access(nbf=int(time.time()) + 600), id="not-yet-valid"),
        pytest.param(lambda: _signed_access(jti=1), id="jti-not-a-string"),
        pytest.param(lambda: _signed_access(aud="someone-else"), id="audience-claim"),
    ],
)
@pytest.mark.asyncio
async def test_an_unverifiable_access_token_is_refused_as_bearer_and_counted_invalid(mint):
    db = await _db_with_user()
    invalid_before = _validations("invalid")

    with pytest.raises(HTTPException) as exc_info:
        await get_current_user(db=db, token=mint())

    assert exc_info.value.status_code == _UNAUTHORIZED
    assert exc_info.value.detail == _MSG_CREDENTIALS
    assert exc_info.value.headers == {"WWW-Authenticate": "Bearer"}
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
async def test_an_access_token_is_checked_without_reading_the_blacklist():
    db = await _db_with_user()
    reads = []
    read = db.token_blacklist.find_one

    async def counted(*args, **kwargs):
        reads.append(args)
        return await read(*args, **kwargs)

    db.token_blacklist.find_one = counted
    await get_current_user(db=db, token=security.create_access_token(_USER_ID))

    assert reads == []


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
