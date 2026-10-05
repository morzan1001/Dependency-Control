"""Small authentication gaps: who may read an account, which passwords are accepted, which sessions survive."""

import threading
from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from pydantic import ValidationError

from app.api import deps
from app.core import security
from app.core.config import Settings, settings
from app.core.permissions import Permissions

_API = settings.API_V1_STR
_BOB_ID = "u-bob"
_ALICE_ID = "u-alice"
_CAROL_ID = "u-carol"
_PASSWORD = "Correct-Horse-1"
_NEW_PASSWORD = "Battery-Staple-2"
_INVITATION_TOKEN = "invitation-token"
_PROJECT_ID = "proj-1"
_PROJECT_SECRET = "project-secret"
_OK = 200
_UNAUTHORIZED = 401
_FORBIDDEN = 403
_UNPROCESSABLE = 422


@pytest_asyncio.fixture
async def api(db):
    from app.main import app

    async def _get_database():
        return db

    app.dependency_overrides[deps.get_database] = _get_database
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            yield client
    finally:
        app.dependency_overrides.pop(deps.get_database, None)


async def _add_user(db, user_id, username, permissions):
    await db.users.insert_one(
        {
            "_id": user_id,
            "username": username,
            "email": f"{username}@test.com",
            "hashed_password": security.get_password_hash(_PASSWORD),
            "is_active": True,
            "is_verified": True,
            "auth_provider": "local",
            "permissions": permissions,
        }
    )


def _bearer(user_id):
    return {"Authorization": f"Bearer {security.create_access_token(user_id)}"}


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_user_read_opens_only_the_own_account(api, db):
    await _add_user(db, _BOB_ID, "bob", [Permissions.USER_READ])
    await _add_user(db, _ALICE_ID, "alice", [])

    other = await api.get(f"{_API}/users/{_ALICE_ID}", headers=_bearer(_BOB_ID))
    own = await api.get(f"{_API}/users/{_BOB_ID}", headers=_bearer(_BOB_ID))

    assert other.status_code == _FORBIDDEN
    assert own.status_code == _OK


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_user_read_all_opens_every_account(api, db):
    await _add_user(db, _CAROL_ID, "carol", [Permissions.USER_READ_ALL])
    await _add_user(db, _ALICE_ID, "alice", [])

    response = await api.get(f"{_API}/users/{_ALICE_ID}", headers=_bearer(_CAROL_ID))

    assert response.status_code == _OK
    assert response.json()["id"] == _ALICE_ID


@pytest.mark.live_mongo
@pytest.mark.asyncio
@pytest.mark.parametrize("weak_password", ["a", "abcdefgh1"])
async def test_accepting_an_invitation_enforces_the_password_policy(api, db, weak_password):
    await db.system_invitations.insert_one(
        {
            "_id": "inv-1",
            "email": "carol@test.com",
            "token": _INVITATION_TOKEN,
            "invited_by": _BOB_ID,
            "expires_at": datetime.now(timezone.utc) + timedelta(days=1),
            "is_used": False,
        }
    )

    response = await api.post(
        f"{_API}/invitations/system/accept",
        json={"token": _INVITATION_TOKEN, "username": "carol", "password": weak_password},
    )

    assert response.status_code == _UNPROCESSABLE
    assert await db.users.count_documents({}) == 0


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_a_password_change_ends_the_sessions_opened_before_it(api, db):
    await _add_user(db, _BOB_ID, "bob", [])
    session = _bearer(_BOB_ID)

    changed = await api.post(
        f"{_API}/users/me/password",
        json={"current_password": _PASSWORD, "new_password": _NEW_PASSWORD},
        headers=session,
    )
    reused = await api.get(f"{_API}/users/me", headers=session)

    assert changed.status_code == _OK
    assert reused.status_code == _UNAUTHORIZED


def test_settings_refuse_to_start_without_a_secret_key(monkeypatch):
    monkeypatch.delenv("SECRET_KEY")

    with pytest.raises(ValidationError, match="SECRET_KEY"):
        Settings(_env_file=None)


@pytest.mark.asyncio
async def test_a_project_key_is_verified_off_the_event_loop_thread(db, monkeypatch):
    await db.projects.insert_one(
        {"_id": _PROJECT_ID, "name": "p", "api_key_hash": security.get_password_hash(_PROJECT_SECRET)}
    )
    real_verify = security.pwd_context.verify
    verify_threads = []

    def recording_verify(secret, hashed):
        verify_threads.append(threading.get_ident())
        return real_verify(secret, hashed)

    monkeypatch.setattr(security.pwd_context, "verify", recording_verify)

    project = await deps.get_project_for_ingest(x_api_key=f"{_PROJECT_ID}.{_PROJECT_SECRET}", oidc_token=None, db=db)

    assert project.id == _PROJECT_ID
    assert verify_threads
    assert threading.get_ident() not in verify_threads
