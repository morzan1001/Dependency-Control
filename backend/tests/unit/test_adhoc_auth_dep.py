"""The ad-hoc token dependency authenticates without writing anything."""

from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import HTTPException

from app.api.deps import get_adhoc_api_key
from app.core.permissions import Permissions
from app.models.user import User
from app.repositories.adhoc_api_keys import hash_token
from tests.mocks.mongodb import create_mock_collection, create_mock_db

_COL = "adhoc_api_keys"
_TOKEN_BODY_CHARS = 60
_TOKEN = "dca_" + "a" * _TOKEN_BODY_CHARS
_PREFIX_LENGTH = 12
_KEY_ID = "key-1"
_OWNER = "user-1"
_KEY_NAME = "ci"
_UNAUTHORIZED = 401
_FORBIDDEN = 403

# Every write create_mock_collection stubs. find_one_and_update is the idiomatic way to write a
# touch-on-read, so leaving it unchecked would let the write this dependency must not do slip in.
_WRITE_METHODS = (
    "insert_one",
    "find_one_and_update",
    "update_one",
    "update_many",
    "delete_one",
    "bulk_write",
    "create_index",
)

# Asserting on the key collection alone leaves a usage or audit collection free to be written.
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
async def test_valid_token_returns_the_key_document(monkeypatch):
    db, _ = _db_with_key(_key_doc())
    _patch_user(monkeypatch, _active_user([Permissions.ANALYZE_ADHOC]))

    key = await get_adhoc_api_key(authorization=f"Bearer {_TOKEN}", db=db)

    assert key["_id"] == _KEY_ID


@pytest.mark.asyncio
async def test_authentication_writes_nothing(monkeypatch):
    db, keys = _db_with_key(_key_doc())
    _patch_user(monkeypatch, _active_user([Permissions.ANALYZE_ADHOC]))

    await get_adhoc_api_key(authorization=f"Bearer {_TOKEN}", db=db)

    for method_name in _WRITE_METHODS:
        method = getattr(keys, method_name)
        # A MagicMock answers assert_not_awaited() with another mock, so a name that is not
        # actually stubbed would assert nothing at all.
        assert isinstance(method, AsyncMock), method_name
        method.assert_not_awaited()


@pytest.mark.asyncio
async def test_authentication_reaches_no_other_collection(monkeypatch):
    db, _ = _db_with_key(_key_doc())
    _patch_user(monkeypatch, _active_user([Permissions.ANALYZE_ADHOC]))

    await get_adhoc_api_key(authorization=f"Bearer {_TOKEN}", db=db)

    by_item = {call.args[0] for call in db.__getitem__.call_args_list}
    assert by_item == _REACHABLE_COLLECTIONS
    # db.some_collection.insert_one(...) never touches __getitem__, but does land in mock_calls.
    by_attribute = {name.split(".")[0] for name, _, _ in db.mock_calls} - {"__getitem__"}
    assert by_attribute <= _REACHABLE_COLLECTIONS


@pytest.mark.asyncio
async def test_missing_header_is_401():
    db, _ = _db_with_key(_key_doc())
    with pytest.raises(HTTPException) as exc:
        await get_adhoc_api_key(authorization="", db=db)
    assert exc.value.status_code == _UNAUTHORIZED


@pytest.mark.asyncio
async def test_unknown_token_is_401():
    db, _ = _db_with_key(None)
    with pytest.raises(HTTPException) as exc:
        await get_adhoc_api_key(authorization=f"Bearer {_TOKEN}", db=db)
    assert exc.value.status_code == _UNAUTHORIZED


@pytest.mark.asyncio
async def test_inactive_owner_is_401(monkeypatch):
    db, _ = _db_with_key(_key_doc())
    inactive = User(id=_OWNER, username="u", email="u@example.com", permissions=[], is_active=False)
    _patch_user(monkeypatch, inactive)
    with pytest.raises(HTTPException) as exc:
        await get_adhoc_api_key(authorization=f"Bearer {_TOKEN}", db=db)
    assert exc.value.status_code == _UNAUTHORIZED


@pytest.mark.asyncio
async def test_owner_without_permission_is_403(monkeypatch):
    db, _ = _db_with_key(_key_doc())
    _patch_user(monkeypatch, _active_user([Permissions.PROJECT_READ]))
    with pytest.raises(HTTPException) as exc:
        await get_adhoc_api_key(authorization=f"Bearer {_TOKEN}", db=db)
    assert exc.value.status_code == _FORBIDDEN
