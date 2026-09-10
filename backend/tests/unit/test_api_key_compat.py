"""The overlap-window resolver: one dependency that admits a unified key and a legacy ad-hoc key
alike, on identical terms, and tells the caller nothing about which of the two stores answered."""

from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException

from app.api.deps import require_api_key_with_legacy
from app.core.constants import API_KEY_SURFACE_ADHOC, API_KEY_SURFACE_MCP
from app.core.permissions import Permissions
from app.repositories.adhoc_api_keys import AdhocApiKeyRepository
from app.repositories.api_keys import ApiKeyRepository
from tests.mocks.fake_mongo import FakeDatabase

_UNIFIED_COL = "api_keys"
_LEGACY_COL = "adhoc_api_keys"
_USERS_COL = "users"

_OWNER = "key-owner"
_KEY_NAME = "ci"
_EXPIRY_DAYS = 30
_TOKEN_BODY_CHARS = 64

_UNAUTHORIZED = 401
_FORBIDDEN = 403

_UNIFIED = "unified"
_LEGACY = "legacy"
_BOTH_KINDS = [_UNIFIED, _LEGACY]

# One message for every miss in either store: a caller who could tell "unknown here" from
# "unknown there" would learn which system still holds their token.
_MSG_OPAQUE_KEY = "Invalid, revoked, or expired API key"

# Every write FakeCollection offers. find_one_and_update is the idiomatic way to write a
# touch-on-read, so leaving it unwatched would let the write the default must not do slip in.
_WRITE_METHODS = (
    "insert_one",
    "insert_many",
    "find_one_and_update",
    "update_one",
    "update_many",
    "delete_one",
    "delete_many",
    "bulk_write",
    "create_index",
)

_WATCHED_COLLECTIONS = (_UNIFIED_COL, _LEGACY_COL, _USERS_COL)


async def _seed_owner(db, permissions=(Permissions.ANALYZE_ADHOC,)):
    await db.users.insert_one(
        {
            "_id": _OWNER,
            "username": _OWNER,
            "email": f"{_OWNER}@example.com",
            "permissions": list(permissions),
            "is_active": True,
            "hashed_password": "x",
        }
    )


async def _mint(db, kind, surfaces=(API_KEY_SURFACE_ADHOC,)):
    if kind == _UNIFIED:
        return await ApiKeyRepository(db).create(_OWNER, _KEY_NAME, list(surfaces), _EXPIRY_DAYS)
    return await AdhocApiKeyRepository(db).create(_OWNER, _KEY_NAME, _EXPIRY_DAYS)


async def _revoke(db, kind, key_id):
    repository = ApiKeyRepository(db) if kind == _UNIFIED else AdhocApiKeyRepository(db)
    assert await repository.revoke(key_id, _OWNER), "the key has to actually be revoked"


async def _resolve(db, token, *, surface=API_KEY_SURFACE_ADHOC, touch=False):
    return await require_api_key_with_legacy(surface, touch=touch)(authorization=f"Bearer {token}", db=db)


def _watch_writes(db):
    spies = {}
    for collection in _WATCHED_COLLECTIONS:
        for method in _WRITE_METHODS:
            spy = AsyncMock(wraps=getattr(db[collection], method))
            setattr(db[collection], method, spy)
            spies[f"{collection}.{method}"] = spy
    return spies


@pytest.mark.parametrize("kind", _BOTH_KINDS)
@pytest.mark.asyncio
async def test_a_key_of_either_kind_is_admitted_with_its_resolved_owner(kind):
    db = FakeDatabase()
    await _seed_owner(db)
    doc, token = await _mint(db, kind)

    user, key_doc = await _resolve(db, token)

    assert user.id == _OWNER
    assert key_doc["_id"] == doc["_id"]
    # The rate limiter downstream reads this field off the key document by name.
    assert key_doc["user_id"] == _OWNER


@pytest.mark.asyncio
async def test_a_unified_key_that_does_not_name_the_surface_is_refused_rather_than_retried():
    """Falling through to the legacy store on a surface refusal would answer 401 instead."""
    db = FakeDatabase()
    await _seed_owner(db, permissions=(Permissions.ANALYZE_ADHOC, Permissions.MCP_ACCESS))
    _doc, token = await _mint(db, _UNIFIED, surfaces=(API_KEY_SURFACE_MCP,))

    with pytest.raises(HTTPException) as exc:
        await _resolve(db, token)

    assert exc.value.status_code == _FORBIDDEN
    assert exc.value.detail == f"API key does not grant the {API_KEY_SURFACE_ADHOC} surface"


@pytest.mark.parametrize("prefix", ["dck_", "dca_"], ids=_BOTH_KINDS)
@pytest.mark.asyncio
async def test_an_unknown_token_of_either_kind_is_401_with_one_shared_message(prefix):
    db = FakeDatabase()
    await _seed_owner(db)

    with pytest.raises(HTTPException) as exc:
        await _resolve(db, prefix + "a" * _TOKEN_BODY_CHARS)

    assert exc.value.status_code == _UNAUTHORIZED
    assert exc.value.detail == _MSG_OPAQUE_KEY
    # A distinguishing signal outside the body would be just as much of an oracle.
    assert exc.value.headers is None


@pytest.mark.parametrize("kind", _BOTH_KINDS)
@pytest.mark.asyncio
async def test_a_revoked_key_of_either_kind_is_401_with_that_same_message(kind):
    db = FakeDatabase()
    await _seed_owner(db)
    doc, token = await _mint(db, kind)
    await _revoke(db, kind, doc["_id"])

    with pytest.raises(HTTPException) as exc:
        await _resolve(db, token)

    assert exc.value.status_code == _UNAUTHORIZED
    assert exc.value.detail == _MSG_OPAQUE_KEY


@pytest.mark.asyncio
async def test_the_legacy_store_is_not_consulted_once_the_unified_lookup_answers():
    db = FakeDatabase()
    await _seed_owner(db)
    _doc, token = await _mint(db, _UNIFIED)
    legacy_lookup = AsyncMock()
    db[_LEGACY_COL].find_one = legacy_lookup

    user, _key_doc = await _resolve(db, token)

    assert user.id == _OWNER
    legacy_lookup.assert_not_awaited()


@pytest.mark.asyncio
async def test_a_legacy_token_costs_the_unified_store_no_round_trip():
    """The prefixes are disjoint, so the unified repository rejects one in memory."""
    db = FakeDatabase()
    await _seed_owner(db)
    _doc, token = await _mint(db, _LEGACY)
    unified_lookup = AsyncMock()
    db[_UNIFIED_COL].find_one = unified_lookup

    user, _key_doc = await _resolve(db, token)

    assert user.id == _OWNER
    unified_lookup.assert_not_awaited()


@pytest.mark.parametrize("kind", _BOTH_KINDS)
@pytest.mark.asyncio
async def test_the_default_writes_nothing_on_either_path(kind):
    db = FakeDatabase()
    await _seed_owner(db)
    _doc, token = await _mint(db, kind)
    spies = _watch_writes(db)

    # Built without touch=, because omitting it is the call shape a surface that persists nothing
    # uses, and the promise belongs to the default rather than to a caller who passes False.
    await require_api_key_with_legacy(API_KEY_SURFACE_ADHOC)(authorization=f"Bearer {token}", db=db)

    for name, spy in spies.items():
        assert not spy.await_count, name


@pytest.mark.asyncio
async def test_touch_stamps_the_unified_key_it_admitted():
    db = FakeDatabase()
    await _seed_owner(db)
    doc, token = await _mint(db, _UNIFIED)

    await _resolve(db, token, touch=True)

    assert (await db[_UNIFIED_COL].find_one({"_id": doc["_id"]}))["last_used_at"] is not None


@pytest.mark.parametrize("kind", _BOTH_KINDS)
@pytest.mark.asyncio
async def test_the_owners_permission_is_required_on_either_path(kind):
    db = FakeDatabase()
    await _seed_owner(db, permissions=(Permissions.PROJECT_READ,))
    _doc, token = await _mint(db, kind)

    with pytest.raises(HTTPException) as exc:
        await _resolve(db, token)

    assert exc.value.status_code == _FORBIDDEN
    assert exc.value.detail == f"Token owner no longer has {API_KEY_SURFACE_ADHOC} access"
