"""Exchanged, spent, superseded and logged-out tokens stop working whatever state the cache is in."""

import asyncio
import re
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch

import jwt
import pyotp
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from app.core import security
from app.core.config import settings
from app.core.permissions import Permissions
from tests.helpers.auth import JOSE_SUBJECT_ID, JOSE_TOKENS

_API = settings.API_V1_STR
_BOB_ID = "u-bob"
_BOB_EMAIL = "bob@test.com"
_PASSWORD = "Correct-Horse-1"
_FIRST_NEW_PASSWORD = "Battery-Staple-2"
_SECOND_NEW_PASSWORD = "Tr0ub4dor-and-3"
_OK = 200
_CREATED = 201
_BAD_REQUEST = 400
_UNAUTHORIZED = 401
_FORBIDDEN = 403
_MSG_CREDENTIALS = "Could not validate credentials"
_MAIL_SETTINGS = {"smtp_host": "smtp.example.com", "emails_from_email": "dc@example.com"}
_TOTP_SECRET = pyotp.random_base32()


class _UnavailableCache:
    """The cache as it answers while Redis is down: nothing stored, nothing kept."""

    async def get(self, key):
        return None

    async def set(self, key, value, ttl_seconds=None):
        return False

    async def incr(self, key, ttl_seconds):
        return None


@pytest_asyncio.fixture
async def api(db):
    from app.api.deps import get_database
    from app.main import app

    async def _get_database():
        return db

    app.dependency_overrides[get_database] = _get_database
    try:
        with patch("app.api.v1.endpoints.auth.cache_service", _UnavailableCache()):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
                yield client
    finally:
        app.dependency_overrides.pop(get_database, None)


@pytest.fixture
def mailbox():
    with patch("app.api.v1.helpers.auth.EmailProvider") as provider:
        provider.return_value.send = AsyncMock()
        yield provider.return_value.send


async def _add_bob(db, **fields):
    await db.users.insert_one(
        {
            "_id": _BOB_ID,
            "username": "bob",
            "email": _BOB_EMAIL,
            "hashed_password": security.get_password_hash(_PASSWORD),
            "is_active": True,
            "is_verified": True,
            "auth_provider": "local",
            "permissions": [],
            **fields,
        }
    )


async def _store_settings(db, **fields):
    await db.system_settings.insert_one({"_id": "current", **fields})


async def _refresh(api, token):
    return await api.post(f"{_API}/login/refresh-token", json={"refresh_token": token})


def _unverified_claims(token):
    return jwt.decode(token, options={"verify_signature": False})


def _expired(token_type):
    return security._create_token(_BOB_ID, token_type, datetime.now(timezone.utc) - timedelta(seconds=1))


async def _request_reset_link(api, mailbox) -> str:
    response = await api.post(f"{_API}/forgot-password", json={"email": _BOB_EMAIL})
    assert response.status_code == _OK
    return re.search(r"token=(\S+)", mailbox.await_args.kwargs["message"]).group(1)


async def _reset(api, token, new_password):
    return await api.post(f"{_API}/reset-password", json={"token": token, "new_password": new_password})


async def _stored_hash(db):
    return (await db.users.find_one({"_id": _BOB_ID}))["hashed_password"]


async def _login(api, username, password, otp=""):
    return await api.post(f"{_API}/login/access-token", data={"username": username, "password": password, "otp": otp})


@pytest.mark.asyncio
async def test_an_exchanged_refresh_token_is_refused_and_its_successor_works(api, db):
    await _add_bob(db)
    presented = security.create_refresh_token(_BOB_ID)

    first = await _refresh(api, presented)
    replay = await _refresh(api, presented)
    successor = await _refresh(api, first.json()["refresh_token"])

    assert first.status_code == _OK
    assert replay.status_code == _FORBIDDEN
    assert successor.status_code == _OK
    claims = _unverified_claims(presented)
    entry = await db.token_blacklist.find_one({"_id": claims["jti"]})
    assert entry["expires_at"] == datetime.fromtimestamp(claims["exp"], tz=timezone.utc)


@pytest.mark.asyncio
async def test_a_session_issued_by_python_jose_keeps_working(api, db):
    await _add_bob(db, _id=JOSE_SUBJECT_ID, username="legacy")

    me = await api.get(f"{_API}/users/me", headers={"Authorization": f"Bearer {JOSE_TOKENS['access']}"})
    refreshed = await _refresh(api, JOSE_TOKENS["refresh"])
    me_after_refresh = await api.get(
        f"{_API}/users/me", headers={"Authorization": f"Bearer {refreshed.json()['access_token']}"}
    )

    assert me.status_code == _OK
    assert me.json()["username"] == "legacy"
    assert refreshed.status_code == _OK
    assert me_after_refresh.status_code == _OK


def _forged_refresh():
    return jwt.encode(
        _unverified_claims(security.create_refresh_token(_BOB_ID)),
        "another-secret-key-long-enough-for-hs256",
        algorithm=settings.ALGORITHM,
    )


@pytest.mark.parametrize(
    "mint",
    [pytest.param(lambda: _expired("refresh"), id="expired"), pytest.param(_forged_refresh, id="forged")],
)
@pytest.mark.asyncio
async def test_an_unverifiable_refresh_token_is_refused(api, db, mint):
    await _add_bob(db)

    response = await _refresh(api, mint())

    assert response.status_code == _FORBIDDEN
    assert response.json()["detail"] == _MSG_CREDENTIALS


@pytest.mark.asyncio
async def test_an_expired_access_token_is_refused_with_a_bearer_challenge(api, db):
    await _add_bob(db)

    response = await api.get(f"{_API}/users/me", headers={"Authorization": f"Bearer {_expired('access')}"})

    assert response.status_code == _UNAUTHORIZED
    assert response.json()["detail"] == _MSG_CREDENTIALS
    assert response.headers["www-authenticate"] == "Bearer"


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_two_concurrent_exchanges_of_one_refresh_token_mint_one_pair(api, db):
    await _add_bob(db)
    presented = security.create_refresh_token(_BOB_ID)

    responses = await asyncio.gather(_refresh(api, presented), _refresh(api, presented))

    assert sorted(r.status_code for r in responses) == [_OK, _FORBIDDEN]


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_a_one_time_code_logs_in_once(api, db):
    await _add_bob(db, totp_enabled=True, totp_secret=_TOTP_SECRET)
    code = pyotp.TOTP(_TOTP_SECRET).now()

    first = await _login(api, "bob", _PASSWORD, code)
    replay = await _login(api, "bob", _PASSWORD, code)

    assert first.status_code == _OK
    assert replay.status_code == _UNAUTHORIZED
    assert replay.json()["detail"] == "Invalid OTP code"


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_two_concurrent_logins_with_one_code_open_one_session(api, db):
    await _add_bob(db, totp_enabled=True, totp_secret=_TOTP_SECRET)
    code = pyotp.TOTP(_TOTP_SECRET).now()

    responses = await asyncio.gather(_login(api, "bob", _PASSWORD, code), _login(api, "bob", _PASSWORD, code))

    assert sorted(r.status_code for r in responses) == [_OK, _UNAUTHORIZED]


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_the_code_that_enabled_2fa_does_not_also_log_in(api, db):
    await _add_bob(db)
    auth = {"Authorization": f"Bearer {security.create_access_token(_BOB_ID)}"}
    secret = (await api.post(f"{_API}/users/me/2fa/setup", headers=auth)).json()["secret"]
    code = pyotp.TOTP(secret).now()

    enabled = await api.post(f"{_API}/users/me/2fa/enable", json={"code": code, "password": _PASSWORD}, headers=auth)
    login = await _login(api, "bob", _PASSWORD, code)

    assert enabled.status_code == _OK
    assert login.status_code == _UNAUTHORIZED


@pytest.mark.asyncio
async def test_setup_on_an_account_with_2fa_enabled_keeps_the_live_secret(api, db):
    await _add_bob(db, totp_enabled=True, totp_secret=_TOTP_SECRET)
    auth = {"Authorization": f"Bearer {security.create_access_token(_BOB_ID)}"}

    response = await api.post(f"{_API}/users/me/2fa/setup", headers=auth)

    assert response.status_code == _BAD_REQUEST
    stored = await db.users.find_one({"_id": _BOB_ID})
    assert (stored["totp_enabled"], stored["totp_secret"]) == (True, _TOTP_SECRET)


@pytest.mark.asyncio
async def test_a_reset_link_stops_working_once_a_newer_one_was_used(api, db, mailbox):
    await _add_bob(db)
    await _store_settings(db, **_MAIL_SETTINGS)
    older = await _request_reset_link(api, mailbox)
    newer = await _request_reset_link(api, mailbox)

    used = await _reset(api, newer, _FIRST_NEW_PASSWORD)
    superseded = await _reset(api, older, _SECOND_NEW_PASSWORD)

    assert used.status_code == _OK
    assert superseded.status_code == _BAD_REQUEST
    assert security.verify_password(_FIRST_NEW_PASSWORD, await _stored_hash(db))


@pytest.mark.asyncio
async def test_a_reset_link_works_once_while_the_cache_is_unavailable(api, db, mailbox):
    await _add_bob(db)
    await _store_settings(db, **_MAIL_SETTINGS)
    link = await _request_reset_link(api, mailbox)

    used = await _reset(api, link, _FIRST_NEW_PASSWORD)
    replayed = await _reset(api, link, _SECOND_NEW_PASSWORD)

    assert used.status_code == _OK
    assert replayed.status_code == _BAD_REQUEST
    assert security.verify_password(_FIRST_NEW_PASSWORD, await _stored_hash(db))


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_two_concurrent_resets_with_one_link_apply_one_password(api, db, mailbox):
    await _add_bob(db)
    await _store_settings(db, **_MAIL_SETTINGS)
    link = await _request_reset_link(api, mailbox)

    first, second = await asyncio.gather(
        _reset(api, link, _FIRST_NEW_PASSWORD), _reset(api, link, _SECOND_NEW_PASSWORD)
    )

    assert sorted([first.status_code, second.status_code]) == [_OK, _BAD_REQUEST]
    applied = _FIRST_NEW_PASSWORD if first.status_code == _OK else _SECOND_NEW_PASSWORD
    assert security.verify_password(applied, await _stored_hash(db))


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_a_reset_link_gives_an_account_migrated_from_sso_its_first_password(api, db, mailbox):
    await _add_bob(db, hashed_password=None)
    await _store_settings(db, **_MAIL_SETTINGS)
    link = await _request_reset_link(api, mailbox)

    reset = await _reset(api, link, _FIRST_NEW_PASSWORD)
    login = await _login(api, "bob", _FIRST_NEW_PASSWORD)

    assert reset.status_code == _OK
    assert login.status_code == _OK


def _minted_a_second_ago(token):
    claims = _unverified_claims(token)
    return jwt.encode({**claims, "iat": claims["iat"] - 1}, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


@pytest.mark.asyncio
async def test_logout_with_a_lowercase_scheme_ends_the_session_without_a_blacklist_write(api, db):
    await _add_bob(db)
    access, refresh = (_minted_a_second_ago(token) for token in security.create_token_pair(_BOB_ID, []))

    response = await api.post(f"{_API}/logout", headers={"Authorization": f"bearer {access}"})
    me = await api.get(f"{_API}/users/me", headers={"Authorization": f"Bearer {access}"})
    refreshed = await _refresh(api, refresh)

    assert response.status_code == _OK
    assert (me.status_code, refreshed.status_code) == (_UNAUTHORIZED, _FORBIDDEN)
    assert await db.token_blacklist.count_documents({}) == 0


@pytest.mark.asyncio
async def test_an_account_an_admin_created_can_log_in_while_verification_is_enforced(api, db):
    await _add_bob(db, permissions=[Permissions.USER_CREATE])
    await _store_settings(db, enforce_email_verification=True)
    admin_token = security.create_access_token(_BOB_ID)

    created = await api.post(
        f"{_API}/users/",
        json={"email": "alice@test.com", "username": "alice", "password": _FIRST_NEW_PASSWORD},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    login = await _login(api, "alice", _FIRST_NEW_PASSWORD)

    assert created.status_code == _CREATED
    assert login.status_code == _OK


@pytest.mark.asyncio
async def test_the_bootstrap_admin_can_log_in_while_verification_is_enforced(api, db, capsys):
    from app.core import init_db as init_db_module

    with patch.object(init_db_module, "get_database", new=AsyncMock(return_value=db)):
        await init_db_module.init_db()
    password = re.search(r"Password: (\S+)", capsys.readouterr().out).group(1)
    await db.system_settings.update_one({"_id": "current"}, {"$set": {"enforce_email_verification": True}}, upsert=True)

    login = await _login(api, "admin", password)

    assert login.status_code == _OK
