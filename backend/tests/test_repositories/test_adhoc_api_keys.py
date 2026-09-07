"""Ad-hoc API keys: hashed at rest, prefix visible, expiry clamped, revoke idempotent."""

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock

import pytest

from app.repositories.adhoc_api_keys import LIST_LIMIT, AdhocApiKeyRepository, hash_token
from tests.mocks.fake_mongo import FakeDatabase

_COL = "adhoc_api_keys"
_OWNER = "user-1"
_STRANGER = "user-2"
_KEY_NAME = "ci"
_OTHER_KEY_NAME = "b"
_EXPIRY_DAYS = 30
_OVERLONG_EXPIRY_DAYS = 5000
_MAX_EXPIRY_DAYS = 365
_TOKEN_PREFIX = "dca_"
_PREFIX_LENGTH = 12
_FOREIGN_PREFIX = "mcp_"
_OVER_THE_PAGE = 3


@pytest.mark.asyncio
async def test_create_stores_hash_and_prefix_never_the_plaintext():
    db = FakeDatabase()
    doc, plaintext = await AdhocApiKeyRepository(db).create(_OWNER, _KEY_NAME, _EXPIRY_DAYS)

    assert plaintext.startswith(_TOKEN_PREFIX)
    assert doc["token_hash"] == hash_token(plaintext)
    assert doc["prefix"] == plaintext[:_PREFIX_LENGTH]
    stored = await db[_COL].find_one({"_id": doc["_id"]})
    assert plaintext not in str(stored)


@pytest.mark.asyncio
async def test_created_key_carries_no_last_used_field():
    """A usage stamp would make the endpoint's non-persistence claim false at the auth layer."""
    db = FakeDatabase()
    doc, _ = await AdhocApiKeyRepository(db).create(_OWNER, _KEY_NAME, _EXPIRY_DAYS)
    assert "last_used_at" not in doc
    assert "last_used_at" not in await db[_COL].find_one({"_id": doc["_id"]})


@pytest.mark.asyncio
async def test_expiry_is_clamped_to_one_year():
    db = FakeDatabase()
    doc, _ = await AdhocApiKeyRepository(db).create(_OWNER, _KEY_NAME, _OVERLONG_EXPIRY_DAYS)
    horizon = datetime.now(timezone.utc) + timedelta(days=_MAX_EXPIRY_DAYS + 1)
    expires_at = doc["expires_at"]
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    assert expires_at < horizon


@pytest.mark.asyncio
async def test_get_by_plaintext_round_trips():
    db = FakeDatabase()
    doc, plaintext = await AdhocApiKeyRepository(db).create(_OWNER, _KEY_NAME, _EXPIRY_DAYS)
    found = await AdhocApiKeyRepository(db).get_by_plaintext(plaintext)
    assert found is not None
    assert found["_id"] == doc["_id"]


@pytest.mark.asyncio
async def test_get_by_plaintext_rejects_a_foreign_prefix_without_a_lookup():
    db = FakeDatabase()
    repo = AdhocApiKeyRepository(db)
    _, plaintext = await repo.create(_OWNER, _KEY_NAME, _EXPIRY_DAYS)
    db[_COL].find_one = AsyncMock()

    foreign = _FOREIGN_PREFIX + plaintext[len(_TOKEN_PREFIX) :]

    assert await repo.get_by_plaintext(foreign) is None
    db[_COL].find_one.assert_not_awaited()


@pytest.mark.asyncio
async def test_expired_key_no_longer_resolves():
    """The TTL index sweeps minutes late, so the expiry clause is what actually stops a stale key."""
    db = FakeDatabase()
    repo = AdhocApiKeyRepository(db)
    doc, plaintext = await repo.create(_OWNER, _KEY_NAME, _EXPIRY_DAYS)
    await db[_COL].update_one(
        {"_id": doc["_id"]},
        {"$set": {"expires_at": datetime.now(timezone.utc) - timedelta(days=_EXPIRY_DAYS)}},
    )

    assert await repo.get_by_plaintext(plaintext) is None


@pytest.mark.asyncio
async def test_revoked_key_no_longer_resolves():
    db = FakeDatabase()
    repo = AdhocApiKeyRepository(db)
    doc, plaintext = await repo.create(_OWNER, _KEY_NAME, _EXPIRY_DAYS)

    assert await repo.revoke(doc["_id"], _OWNER) is True
    assert await repo.get_by_plaintext(plaintext) is None
    assert await repo.revoke(doc["_id"], _OWNER) is False


@pytest.mark.asyncio
async def test_revoke_requires_ownership():
    db = FakeDatabase()
    repo = AdhocApiKeyRepository(db)
    doc, _ = await repo.create(_OWNER, _KEY_NAME, _EXPIRY_DAYS)
    assert await repo.revoke(doc["_id"], _STRANGER) is False


@pytest.mark.asyncio
async def test_list_for_user_is_scoped():
    db = FakeDatabase()
    repo = AdhocApiKeyRepository(db)
    await repo.create(_OWNER, _KEY_NAME, _EXPIRY_DAYS)
    await repo.create(_STRANGER, _OTHER_KEY_NAME, _EXPIRY_DAYS)
    keys, total = await repo.list_for_user(_OWNER)
    assert [k["name"] for k in keys] == [_KEY_NAME]
    assert total == 1


@pytest.mark.asyncio
async def test_list_for_user_reports_the_population_behind_a_saturated_page():
    """Returning LIST_LIMIT rows and calling that the whole holding hides keys the owner
    still has to revoke."""
    db = FakeDatabase()
    repo = AdhocApiKeyRepository(db)
    for index in range(LIST_LIMIT + _OVER_THE_PAGE):
        await repo.create(_OWNER, f"{_KEY_NAME}-{index}", _EXPIRY_DAYS)

    keys, total = await repo.list_for_user(_OWNER)

    assert len(keys) == LIST_LIMIT
    assert total == LIST_LIMIT + _OVER_THE_PAGE
