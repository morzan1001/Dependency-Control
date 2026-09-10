"""MCP API keys: hashed at rest, prefix visible, expiry clamped, revoke idempotent, usage stamped."""

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock

import pytest

from app.repositories.mcp_api_keys import LIST_LIMIT, MCPApiKeyRepository, hash_token
from tests.mocks.fake_mongo import FakeDatabase

_COL = "mcp_api_keys"
_OWNER = "user-1"
_STRANGER = "user-2"
_KEY_NAME = "client"
_OTHER_KEY_NAME = "b"
_EXPIRY_DAYS = 30
_OVERLONG_EXPIRY_DAYS = 5000
_MAX_EXPIRY_DAYS = 365
_TOKEN_PREFIX = "mcp_"
_PREFIX_LENGTH = 12
_FOREIGN_PREFIX = "dca_"
_OVER_THE_PAGE = 3
_ONE_KEY = 1
_STALE_DAYS = 1


@pytest.mark.asyncio
async def test_create_stores_hash_and_prefix_never_the_plaintext():
    db = FakeDatabase()
    doc, plaintext = await MCPApiKeyRepository(db).create(_OWNER, _KEY_NAME, _EXPIRY_DAYS)

    assert plaintext.startswith(_TOKEN_PREFIX)
    assert doc["token_hash"] == hash_token(plaintext)
    assert doc["prefix"] == plaintext[:_PREFIX_LENGTH]
    stored = await db[_COL].find_one({"_id": doc["_id"]})
    assert plaintext not in str(stored)


@pytest.mark.asyncio
async def test_created_key_carries_a_null_last_used_field():
    """The inverse of the ad-hoc key, which has no such field: an MCP key is stamped on every
    authentication, so the field exists from creation and reads null until first use."""
    db = FakeDatabase()
    doc, _ = await MCPApiKeyRepository(db).create(_OWNER, _KEY_NAME, _EXPIRY_DAYS)

    assert doc["last_used_at"] is None
    assert (await db[_COL].find_one({"_id": doc["_id"]}))["last_used_at"] is None


@pytest.mark.asyncio
async def test_expiry_is_clamped_to_one_year():
    db = FakeDatabase()
    doc, _ = await MCPApiKeyRepository(db).create(_OWNER, _KEY_NAME, _OVERLONG_EXPIRY_DAYS)
    horizon = datetime.now(timezone.utc) + timedelta(days=_MAX_EXPIRY_DAYS + 1)
    expires_at = doc["expires_at"]
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    assert expires_at < horizon


@pytest.mark.asyncio
async def test_get_by_plaintext_round_trips():
    db = FakeDatabase()
    doc, plaintext = await MCPApiKeyRepository(db).create(_OWNER, _KEY_NAME, _EXPIRY_DAYS)
    found = await MCPApiKeyRepository(db).get_by_plaintext(plaintext)
    assert found is not None
    assert found["_id"] == doc["_id"]


@pytest.mark.asyncio
async def test_get_by_plaintext_rejects_a_foreign_prefix_without_a_lookup():
    db = FakeDatabase()
    repo = MCPApiKeyRepository(db)
    _, plaintext = await repo.create(_OWNER, _KEY_NAME, _EXPIRY_DAYS)
    db[_COL].find_one = AsyncMock()

    foreign = _FOREIGN_PREFIX + plaintext[len(_TOKEN_PREFIX) :]

    assert await repo.get_by_plaintext(foreign) is None
    db[_COL].find_one.assert_not_awaited()


@pytest.mark.asyncio
async def test_expired_key_no_longer_resolves():
    """The TTL index sweeps minutes late, so the expiry clause is what actually stops a stale key."""
    db = FakeDatabase()
    repo = MCPApiKeyRepository(db)
    doc, plaintext = await repo.create(_OWNER, _KEY_NAME, _EXPIRY_DAYS)
    await db[_COL].update_one(
        {"_id": doc["_id"]},
        {"$set": {"expires_at": datetime.now(timezone.utc) - timedelta(days=_EXPIRY_DAYS)}},
    )

    assert await repo.get_by_plaintext(plaintext) is None


@pytest.mark.asyncio
async def test_revoked_key_no_longer_resolves():
    db = FakeDatabase()
    repo = MCPApiKeyRepository(db)
    doc, plaintext = await repo.create(_OWNER, _KEY_NAME, _EXPIRY_DAYS)

    assert await repo.revoke(doc["_id"], _OWNER) is True
    assert await repo.get_by_plaintext(plaintext) is None
    assert await repo.revoke(doc["_id"], _OWNER) is False


@pytest.mark.asyncio
async def test_revoke_requires_ownership():
    db = FakeDatabase()
    repo = MCPApiKeyRepository(db)
    doc, _ = await repo.create(_OWNER, _KEY_NAME, _EXPIRY_DAYS)
    assert await repo.revoke(doc["_id"], _STRANGER) is False


@pytest.mark.asyncio
async def test_list_for_user_is_scoped():
    db = FakeDatabase()
    repo = MCPApiKeyRepository(db)
    await repo.create(_OWNER, _KEY_NAME, _EXPIRY_DAYS)
    await repo.create(_STRANGER, _OTHER_KEY_NAME, _EXPIRY_DAYS)
    keys, total = await repo.list_for_user(_OWNER)
    assert [k["name"] for k in keys] == [_KEY_NAME]
    assert total == _ONE_KEY


@pytest.mark.asyncio
async def test_list_for_user_reports_the_population_behind_a_saturated_page():
    """An MCP key reaches every tool the owner can, so one they cannot see is one they
    cannot revoke."""
    db = FakeDatabase()
    repo = MCPApiKeyRepository(db)
    for index in range(LIST_LIMIT + _OVER_THE_PAGE):
        await repo.create(_OWNER, f"{_KEY_NAME}-{index}", _EXPIRY_DAYS)

    keys, total = await repo.list_for_user(_OWNER)

    assert len(keys) == LIST_LIMIT
    assert total == LIST_LIMIT + _OVER_THE_PAGE


@pytest.mark.asyncio
async def test_a_complete_listing_costs_no_count_round_trip():
    """A page that did not saturate already knows the total, so the count has to be skipped and
    not merely agree — asserting on the number alone passes however many round trips it took."""
    db = FakeDatabase()
    repo = MCPApiKeyRepository(db)
    await repo.create(_OWNER, _KEY_NAME, _EXPIRY_DAYS)
    counted = AsyncMock(wraps=db[_COL].count_documents)
    db[_COL].count_documents = counted

    keys, total = await repo.list_for_user(_OWNER)

    assert total == len(keys)
    counted.assert_not_awaited()


@pytest.mark.asyncio
async def test_touch_last_used_moves_the_timestamp_forward():
    """The stamp is what tells an owner a key is still in use before they revoke it; the seeded
    stale value makes the advance strict, since BSON floors dates to whole milliseconds and a
    fresh key's two stamps otherwise land in the same one."""
    db = FakeDatabase()
    repo = MCPApiKeyRepository(db)
    doc, _ = await repo.create(_OWNER, _KEY_NAME, _EXPIRY_DAYS)
    assert (await db[_COL].find_one({"_id": doc["_id"]}))["last_used_at"] is None
    stale = datetime.now(timezone.utc) - timedelta(days=_STALE_DAYS)
    await db[_COL].update_one({"_id": doc["_id"]}, {"$set": {"last_used_at": stale}})

    await repo.touch_last_used(doc["_id"])

    stored = await db[_COL].find_one({"_id": doc["_id"]})
    assert stored["last_used_at"] > stale.replace(tzinfo=None)
