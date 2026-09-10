"""The MCP token resolver authenticates the key owner and stamps the key as used."""

from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import HTTPException

from app.api.v1.endpoints.mcp import _resolve_user_from_token
from app.core.permissions import Permissions
from app.models.user import User
from app.repositories.mcp_api_keys import hash_token
from tests.mocks.mongodb import create_mock_collection, create_mock_db

_COL = "mcp_api_keys"
_TOKEN_BODY_CHARS = 64
_TOKEN = "mcp_" + "a" * _TOKEN_BODY_CHARS
_PREFIX_LENGTH = 12
_KEY_ID = "key-1"
_OWNER = "user-1"
_KEY_NAME = "claude-desktop"
_UNAUTHORIZED = 401
_FORBIDDEN = 403

# Unknown, revoked and expired share one message: distinguishing them would confirm to a caller
# holding a rejected token that the token once existed.
_OPAQUE_KEY_DETAIL = "Invalid, revoked, or expired MCP API key"

# Asserting on the key collection alone leaves a usage or audit collection free to be read.
_USERS_COL = "users"
_REACHABLE_COLLECTIONS = frozenset({_COL, _USERS_COL})


def _key_doc():
    return {
        "_id": _KEY_ID,
        "user_id": _OWNER,
        "name": _KEY_NAME,
        "prefix": _TOKEN[:_PREFIX_LENGTH],
        "token_hash": hash_token(_TOKEN),
        "revoked_at": None,
    }


def _db_with_key(doc):
    keys = create_mock_collection(find_one=doc)
    # get_by_plaintext reads through with_options(read_preference=PRIMARY); create_mock_collection
    # does not stub it, so the strong-read alias has to point back at the same mock.
    keys.with_options = MagicMock(return_value=keys)
    return create_mock_db({_COL: keys}), keys


def _patch_user(monkeypatch, user):
    monkeypatch.setattr(
        "app.repositories.users.UserRepository.get_by_id",
        AsyncMock(return_value=user),
    )


def _active_user(permissions):
    return User(id=_OWNER, username="u", email="u@example.com", permissions=permissions, is_active=True)


@pytest.mark.asyncio
async def test_a_valid_token_returns_the_owner_and_the_key_document(monkeypatch):
    db, _ = _db_with_key(_key_doc())
    _patch_user(monkeypatch, _active_user([Permissions.MCP_ACCESS]))

    user, key_doc = await _resolve_user_from_token(f"Bearer {_TOKEN}", db)

    assert user.id == _OWNER
    assert key_doc["_id"] == _KEY_ID


@pytest.mark.asyncio
async def test_a_missing_header_is_401():
    db, _ = _db_with_key(_key_doc())

    with pytest.raises(HTTPException) as exc:
        await _resolve_user_from_token("", db)

    assert exc.value.status_code == _UNAUTHORIZED


@pytest.mark.asyncio
async def test_a_non_bearer_header_is_401():
    db, _ = _db_with_key(_key_doc())

    with pytest.raises(HTTPException) as exc:
        await _resolve_user_from_token(_TOKEN, db)

    assert exc.value.status_code == _UNAUTHORIZED


@pytest.mark.asyncio
async def test_an_unknown_token_is_401():
    db, _ = _db_with_key(None)

    with pytest.raises(HTTPException) as exc:
        await _resolve_user_from_token(f"Bearer {_TOKEN}", db)

    assert exc.value.status_code == _UNAUTHORIZED
    assert exc.value.detail == _OPAQUE_KEY_DETAIL


@pytest.mark.asyncio
async def test_an_inactive_owner_is_401(monkeypatch):
    db, _ = _db_with_key(_key_doc())
    inactive = User(
        id=_OWNER,
        username="u",
        email="u@example.com",
        permissions=[Permissions.MCP_ACCESS],
        is_active=False,
    )
    _patch_user(monkeypatch, inactive)

    with pytest.raises(HTTPException) as exc:
        await _resolve_user_from_token(f"Bearer {_TOKEN}", db)

    assert exc.value.status_code == _UNAUTHORIZED


@pytest.mark.asyncio
async def test_an_owner_without_mcp_access_is_403(monkeypatch):
    db, _ = _db_with_key(_key_doc())
    _patch_user(monkeypatch, _active_user([Permissions.PROJECT_READ]))

    with pytest.raises(HTTPException) as exc:
        await _resolve_user_from_token(f"Bearer {_TOKEN}", db)

    assert exc.value.status_code == _FORBIDDEN


@pytest.mark.asyncio
async def test_authentication_stamps_last_used(monkeypatch):
    db, _ = _db_with_key(_key_doc())
    _patch_user(monkeypatch, _active_user([Permissions.MCP_ACCESS]))
    touch = AsyncMock()
    monkeypatch.setattr("app.repositories.mcp_api_keys.MCPApiKeyRepository.touch_last_used", touch)

    await _resolve_user_from_token(f"Bearer {_TOKEN}", db)

    touch.assert_awaited_once_with(_KEY_ID)


@pytest.mark.asyncio
async def test_authentication_reaches_no_collection_beyond_keys_and_users(monkeypatch):
    db, _ = _db_with_key(_key_doc())
    _patch_user(monkeypatch, _active_user([Permissions.MCP_ACCESS]))

    await _resolve_user_from_token(f"Bearer {_TOKEN}", db)

    by_item = {call.args[0] for call in db.__getitem__.call_args_list}
    assert by_item == _REACHABLE_COLLECTIONS
    # db.some_collection.insert_one(...) never touches __getitem__, but does land in mock_calls.
    by_attribute = {name.split(".")[0] for name, _, _ in db.mock_calls} - {"__getitem__"}
    assert by_attribute <= _REACHABLE_COLLECTIONS
