"""Tokens name the account by its immutable id: a username can pass to someone else, so a token
naming one would outlive a rename and open whichever account takes the name next."""

import time
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch
from urllib.parse import parse_qs, urlsplit

import pytest
from fastapi import HTTPException
from jose import jwt

from app.core import security
from app.core.config import settings
from app.models.system import SystemSettings
from tests.mocks.fake_mongo import FakeDatabase

MODULE = "app.api.v1.endpoints.auth"
_BAD_REQUEST = 400
_FORBIDDEN = 403
_NOT_FOUND = 404
_PASSWORD = "Correct-Horse-1"
_BOB = {"_id": "u-bob", "username": "bob", "email": "bob@test.com", "is_active": True, "permissions": ["scan:read"]}
_OIDC_SETTINGS = SystemSettings(
    oidc_enabled=True,
    oidc_token_endpoint="https://idp.example/token",
    oidc_userinfo_endpoint="https://idp.example/userinfo",
)


def _subject(token: str) -> str:
    return jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])["sub"]


async def _db_with(*users: dict) -> FakeDatabase:
    db = FakeDatabase()
    for user in users:
        await db.users.insert_one(dict(user))
    return db


async def _refresh(token: str, db: FakeDatabase) -> dict:
    from app.api.v1.endpoints.auth import refresh_token

    with patch(f"{MODULE}.deps.get_system_settings", new=AsyncMock(return_value=SystemSettings())):
        return await refresh_token(refresh_token=token, db=db)


@pytest.mark.asyncio
async def test_a_password_login_names_the_account_by_id():
    from app.api.v1.endpoints.auth import login_access_token

    db = await _db_with({**_BOB, "hashed_password": security.get_password_hash(_PASSWORD)})
    form = SimpleNamespace(username="bob", password=_PASSWORD)

    with (
        patch(f"{MODULE}._check_rate_limit", new_callable=AsyncMock),
        patch(f"{MODULE}.deps.get_system_settings", new=AsyncMock(return_value=SystemSettings())),
    ):
        tokens = await login_access_token(form_data=form, db=db, otp=None)

    assert _subject(tokens["access_token"]) == "u-bob"
    assert _subject(tokens["refresh_token"]) == "u-bob"


@pytest.mark.asyncio
async def test_a_refresh_token_keeps_working_after_the_account_is_renamed():
    db = await _db_with(_BOB)
    token = security.create_refresh_token("u-bob")
    await db.users.update_one({"_id": "u-bob"}, {"$set": {"username": "robert"}})

    tokens = await _refresh(token, db)

    assert _subject(tokens["access_token"]) == "u-bob"
    assert _subject(tokens["refresh_token"]) == "u-bob"


@pytest.mark.asyncio
async def test_a_refresh_token_naming_a_username_is_refused():
    db = await _db_with(_BOB)

    with pytest.raises(HTTPException) as exc_info:
        await _refresh(security.create_refresh_token("bob"), db)

    assert exc_info.value.status_code == _NOT_FOUND


@pytest.fixture
def local_zone_ahead_of_utc(monkeypatch):
    # The pod's zone must not shift the logout comparison.
    monkeypatch.setenv("TZ", "Etc/GMT-2")
    time.tzset()
    yield
    monkeypatch.undo()
    time.tzset()


@pytest.mark.asyncio
@pytest.mark.usefixtures("local_zone_ahead_of_utc")
async def test_ending_every_session_refuses_a_token_minted_for_a_username_equal_to_an_account_id():
    # A user renamed to bob's id before the switch got a refresh token naming "u-bob"; the rollout
    # ends every session at once because by-id lookup cannot tell that token from bob's own.
    db = await _db_with(_BOB, {"_id": "u-eve", "username": "eve", "email": "eve@test.com", "is_active": True})
    minted_before = datetime.now(timezone.utc) - timedelta(hours=1)
    token = jwt.encode(
        {"sub": "u-bob", "type": "refresh", "iat": minted_before, "exp": minted_before + timedelta(days=7)},
        settings.SECRET_KEY,
        algorithm=settings.ALGORITHM,
    )
    await db.users.update_many({}, {"$set": {"last_logout_at": datetime.now(timezone.utc)}})

    with pytest.raises(HTTPException) as exc_info:
        await _refresh(token, db)

    assert exc_info.value.status_code == _FORBIDDEN


async def _oidc_callback(user_info: dict, db: FakeDatabase):
    from app.api.v1.endpoints.auth import login_oidc_callback

    with (
        patch(f"{MODULE}.deps.get_system_settings", new=AsyncMock(return_value=_OIDC_SETTINGS)),
        patch(f"{MODULE}._validate_oidc_state", new_callable=AsyncMock),
        patch(f"{MODULE}._fetch_oidc_user_info", new=AsyncMock(return_value=user_info)),
    ):
        return await login_oidc_callback(request=MagicMock(), code="code", db=db, state="state")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "claim",
    [False, "false", "False", "FALSE", " false ", "0", 0],
    ids=["boolean", "string", "capitalised", "upper", "padded", "zero-string", "zero"],
)
async def test_an_oidc_login_whose_email_the_provider_has_not_verified_is_refused(claim):
    db = await _db_with()

    with pytest.raises(HTTPException) as exc_info:
        await _oidc_callback({"email": "new@corp.com", "email_verified": claim}, db)

    assert exc_info.value.status_code == _BAD_REQUEST
    assert await db.users.find_one({"email": "new@corp.com"}) is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "claims",
    [{}, {"email_verified": True}, {"email_verified": "True"}, {"email_verified": None}],
    ids=["claim-absent", "claim-true", "claim-true-string", "claim-null"],
)
async def test_an_oidc_login_names_the_account_by_id(claims):
    db = await _db_with()

    response = await _oidc_callback({"email": "new@corp.com", "preferred_username": "newbie", **claims}, db)

    created = await db.users.find_one({"email": "new@corp.com"})
    fragment = parse_qs(urlsplit(response.headers["location"]).fragment)
    assert _subject(fragment["access_token"][0]) == str(created["_id"])
    assert _subject(fragment["refresh_token"][0]) == str(created["_id"])
