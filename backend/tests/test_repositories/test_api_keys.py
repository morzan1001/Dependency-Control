"""Unified API keys: hashed at rest, surfaces validated on write, expiry clamped, revoke idempotent."""

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest
from pymongo import ReadPreference

from app.core.constants import API_KEY_SURFACE_ADHOC, API_KEY_SURFACE_MCP
from app.repositories.api_keys import LIST_LIMIT, ApiKeyRepository, generate_plaintext_token, hash_token
from tests.mocks.fake_mongo import FakeDatabase

_COL = "api_keys"
_OWNER = "user-1"
_STRANGER = "user-2"
_KEY_NAME = "client"
_OTHER_KEY_NAME = "b"
_EXPIRY_DAYS = 30
_OVERLONG_EXPIRY_DAYS = 5000
_MAX_EXPIRY_DAYS = 365
_TOKEN_PREFIX = "dck_"
_TOKEN_BODY_CHARS = 64
_PREFIX_LENGTH = 12
_FOREIGN_PREFIX = "xxx_"
_OVER_THE_PAGE = 3
_ONE_KEY = 1
_NO_KEYS = 0
_STALE_DAYS = 1
_SAMPLES = 200
_BOTH_SURFACES = [API_KEY_SURFACE_MCP, API_KEY_SURFACE_ADHOC]
_MCP_ONLY = [API_KEY_SURFACE_MCP]
_UNKNOWN_SURFACE = "admin"
_SURFACE_ERROR = "non-empty subset"
_NEWEST_AGE_DAYS = 0
_MIDDLE_AGE_DAYS = 1
_OLDEST_AGE_DAYS = 2
_BELOW_THE_FLOOR_DAYS = [0, -1]
_MISSING_KEY_ID = "no-such-key"


@pytest.mark.asyncio
async def test_create_stores_the_hash_and_prefix_never_the_plaintext():
    db = FakeDatabase()
    doc, plaintext = await ApiKeyRepository(db).create(_OWNER, _KEY_NAME, _BOTH_SURFACES, _EXPIRY_DAYS)

    assert plaintext.startswith(_TOKEN_PREFIX)
    assert doc["token_hash"] == hash_token(plaintext)
    assert doc["prefix"] == plaintext[:_PREFIX_LENGTH]
    assert isinstance(doc["_id"], str)
    stored = await db[_COL].find_one({"_id": doc["_id"]})
    assert plaintext not in str(stored)


@pytest.mark.asyncio
async def test_create_records_the_requested_surfaces():
    db = FakeDatabase()
    doc, _ = await ApiKeyRepository(db).create(_OWNER, _KEY_NAME, _MCP_ONLY, _EXPIRY_DAYS)

    assert doc["surfaces"] == _MCP_ONLY
    assert (await db[_COL].find_one({"_id": doc["_id"]}))["surfaces"] == _MCP_ONLY


@pytest.mark.asyncio
async def test_create_rejects_an_unknown_surface():
    """A surface nothing serves is a key whose reach nobody can reason about."""
    db = FakeDatabase()

    with pytest.raises(ValueError, match=_SURFACE_ERROR):
        await ApiKeyRepository(db).create(_OWNER, _KEY_NAME, [API_KEY_SURFACE_MCP, _UNKNOWN_SURFACE], _EXPIRY_DAYS)

    assert await db[_COL].count_documents({}) == _NO_KEYS


@pytest.mark.asyncio
async def test_create_rejects_an_empty_surface_list():
    """A key that opens no door is a mistake, not a default."""
    db = FakeDatabase()

    with pytest.raises(ValueError, match=_SURFACE_ERROR):
        await ApiKeyRepository(db).create(_OWNER, _KEY_NAME, [], _EXPIRY_DAYS)

    assert await db[_COL].count_documents({}) == _NO_KEYS


@pytest.mark.asyncio
async def test_create_deduplicates_repeated_surfaces():
    db = FakeDatabase()
    doc, _ = await ApiKeyRepository(db).create(
        _OWNER, _KEY_NAME, [API_KEY_SURFACE_MCP, API_KEY_SURFACE_MCP], _EXPIRY_DAYS
    )

    assert doc["surfaces"] == _MCP_ONLY


@pytest.mark.asyncio
async def test_a_created_key_carries_a_null_last_used_stamp():
    db = FakeDatabase()
    doc, _ = await ApiKeyRepository(db).create(_OWNER, _KEY_NAME, _BOTH_SURFACES, _EXPIRY_DAYS)

    assert doc["last_used_at"] is None
    assert (await db[_COL].find_one({"_id": doc["_id"]}))["last_used_at"] is None


def test_the_token_body_is_always_64_characters():
    """A url-safe encoding stripped of its punctuation yields a shorter body on most draws, so
    a single sample would agree with a generator whose length is in fact variable."""
    lengths = {len(generate_plaintext_token()) - len(_TOKEN_PREFIX) for _ in range(_SAMPLES)}

    assert lengths == {_TOKEN_BODY_CHARS}


def test_generated_tokens_are_unique():
    tokens = {generate_plaintext_token() for _ in range(_SAMPLES)}

    assert len(tokens) == _SAMPLES


@pytest.mark.asyncio
async def test_expiry_is_clamped_to_one_year():
    db = FakeDatabase()
    doc, _ = await ApiKeyRepository(db).create(_OWNER, _KEY_NAME, _BOTH_SURFACES, _OVERLONG_EXPIRY_DAYS)
    horizon = datetime.now(timezone.utc) + timedelta(days=_MAX_EXPIRY_DAYS + 1)
    expires_at = doc["expires_at"]
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    assert expires_at < horizon


@pytest.mark.asyncio
async def test_the_requested_lifetime_is_honoured():
    """Both stamps come from one clock reading, so the span is exact: a wrong unit or a lifetime
    that ignores the request survives a ceiling-only assertion."""
    db = FakeDatabase()
    doc, _ = await ApiKeyRepository(db).create(_OWNER, _KEY_NAME, _BOTH_SURFACES, _EXPIRY_DAYS)

    assert doc["expires_at"] - doc["created_at"] == timedelta(days=_EXPIRY_DAYS)


@pytest.mark.asyncio
@pytest.mark.parametrize("expires_in_days", _BELOW_THE_FLOOR_DAYS)
async def test_an_expiry_under_a_day_is_lifted_to_the_floor(expires_in_days):
    """Without the floor the key expires no later than it was minted, and the `$gt: now` clause
    turns it down on its very first use — a key that never authenticates at all."""
    db = FakeDatabase()
    repo = ApiKeyRepository(db)
    _, plaintext = await repo.create(_OWNER, _KEY_NAME, _BOTH_SURFACES, expires_in_days)

    assert await repo.get_by_plaintext(plaintext) is not None


@pytest.mark.asyncio
async def test_get_by_plaintext_round_trips():
    db = FakeDatabase()
    doc, plaintext = await ApiKeyRepository(db).create(_OWNER, _KEY_NAME, _BOTH_SURFACES, _EXPIRY_DAYS)

    found = await ApiKeyRepository(db).get_by_plaintext(plaintext)

    assert found is not None
    assert found["_id"] == doc["_id"]


@pytest.mark.asyncio
async def test_get_by_plaintext_reads_from_the_primary():
    """The client carries a configurable read preference, so an authentication left on the default
    resolves a revoked key off a lagging secondary for as long as the lag lasts. The fake returns
    itself from `with_options`, which is why the call has to be observed rather than its effect."""
    db = FakeDatabase()
    repo = ApiKeyRepository(db)
    _, plaintext = await repo.create(_OWNER, _KEY_NAME, _BOTH_SURFACES, _EXPIRY_DAYS)
    observed = MagicMock(wraps=db[_COL].with_options)
    db[_COL].with_options = observed

    assert await repo.get_by_plaintext(plaintext) is not None
    observed.assert_called_once_with(read_preference=ReadPreference.PRIMARY)


@pytest.mark.asyncio
async def test_get_by_plaintext_rejects_a_foreign_prefix_without_a_lookup():
    db = FakeDatabase()
    repo = ApiKeyRepository(db)
    _, plaintext = await repo.create(_OWNER, _KEY_NAME, _BOTH_SURFACES, _EXPIRY_DAYS)
    db[_COL].find_one = AsyncMock()

    foreign = _FOREIGN_PREFIX + plaintext[len(_TOKEN_PREFIX) :]

    assert await repo.get_by_plaintext(foreign) is None
    db[_COL].find_one.assert_not_awaited()


@pytest.mark.asyncio
async def test_an_expired_key_no_longer_resolves():
    """The TTL index sweeps minutes late, so the expiry clause is what actually stops a stale key."""
    db = FakeDatabase()
    repo = ApiKeyRepository(db)
    doc, plaintext = await repo.create(_OWNER, _KEY_NAME, _BOTH_SURFACES, _EXPIRY_DAYS)
    await db[_COL].update_one(
        {"_id": doc["_id"]},
        {"$set": {"expires_at": datetime.now(timezone.utc) - timedelta(days=_EXPIRY_DAYS)}},
    )

    assert await repo.get_by_plaintext(plaintext) is None


@pytest.mark.asyncio
async def test_a_revoked_key_no_longer_resolves():
    db = FakeDatabase()
    repo = ApiKeyRepository(db)
    doc, plaintext = await repo.create(_OWNER, _KEY_NAME, _BOTH_SURFACES, _EXPIRY_DAYS)

    assert await repo.revoke(doc["_id"], _OWNER) is True
    assert await repo.get_by_plaintext(plaintext) is None


@pytest.mark.asyncio
async def test_revoke_requires_ownership():
    db = FakeDatabase()
    repo = ApiKeyRepository(db)
    doc, plaintext = await repo.create(_OWNER, _KEY_NAME, _BOTH_SURFACES, _EXPIRY_DAYS)

    assert await repo.revoke(doc["_id"], _STRANGER) is False
    assert await repo.get_by_plaintext(plaintext) is not None


@pytest.mark.asyncio
async def test_revoke_is_idempotent():
    """The stamp is rewound between the calls so the second one is provably a no-op: two revokes
    landing in the same millisecond leave BSON's floored timestamp identical either way."""
    db = FakeDatabase()
    repo = ApiKeyRepository(db)
    doc, _ = await repo.create(_OWNER, _KEY_NAME, _BOTH_SURFACES, _EXPIRY_DAYS)
    assert await repo.revoke(doc["_id"], _OWNER) is True
    stale = datetime.now(timezone.utc) - timedelta(days=_STALE_DAYS)
    await db[_COL].update_one({"_id": doc["_id"]}, {"$set": {"revoked_at": stale}})
    first_stamp = (await db[_COL].find_one({"_id": doc["_id"]}))["revoked_at"]

    assert await repo.revoke(doc["_id"], _OWNER) is False
    assert (await db[_COL].find_one({"_id": doc["_id"]}))["revoked_at"] == first_stamp


@pytest.mark.asyncio
async def test_list_for_user_is_scoped():
    db = FakeDatabase()
    repo = ApiKeyRepository(db)
    await repo.create(_OWNER, _KEY_NAME, _BOTH_SURFACES, _EXPIRY_DAYS)
    await repo.create(_STRANGER, _OTHER_KEY_NAME, _BOTH_SURFACES, _EXPIRY_DAYS)

    keys, total = await repo.list_for_user(_OWNER)

    assert [key["name"] for key in keys] == [_KEY_NAME]
    assert total == _ONE_KEY


@pytest.mark.asyncio
async def test_list_for_user_reports_the_population_behind_a_saturated_page():
    """One key an owner cannot see is one they cannot revoke."""
    db = FakeDatabase()
    repo = ApiKeyRepository(db)
    for index in range(LIST_LIMIT + _OVER_THE_PAGE):
        await repo.create(_OWNER, f"{_KEY_NAME}-{index}", _BOTH_SURFACES, _EXPIRY_DAYS)

    keys, total = await repo.list_for_user(_OWNER)

    assert len(keys) == LIST_LIMIT
    assert total == LIST_LIMIT + _OVER_THE_PAGE


@pytest.mark.asyncio
async def test_list_for_user_returns_the_newest_first():
    """The page truncates at LIST_LIMIT, so the order decides which keys an owner ever sees;
    the ages are seeded out of insertion order to keep the assertion about the sort."""
    db = FakeDatabase()
    repo = ApiKeyRepository(db)
    ages = {"oldest": _OLDEST_AGE_DAYS, "newest": _NEWEST_AGE_DAYS, "middle": _MIDDLE_AGE_DAYS}
    now = datetime.now(timezone.utc)
    for name, age_days in ages.items():
        doc, _ = await repo.create(_OWNER, name, _BOTH_SURFACES, _EXPIRY_DAYS)
        await db[_COL].update_one({"_id": doc["_id"]}, {"$set": {"created_at": now - timedelta(days=age_days)}})

    keys, _ = await repo.list_for_user(_OWNER)

    assert [key["name"] for key in keys] == ["newest", "middle", "oldest"]


@pytest.mark.asyncio
async def test_touch_last_used_moves_the_stamp_forward():
    """BSON floors dates to whole milliseconds, so a fresh key's two stamps would otherwise land
    in the same one and the advance could not be strict."""
    db = FakeDatabase()
    repo = ApiKeyRepository(db)
    doc, _ = await repo.create(_OWNER, _KEY_NAME, _BOTH_SURFACES, _EXPIRY_DAYS)
    stale = datetime.now(timezone.utc) - timedelta(days=_STALE_DAYS)
    await db[_COL].update_one({"_id": doc["_id"]}, {"$set": {"last_used_at": stale}})

    await repo.touch_last_used(doc["_id"])

    stored = await db[_COL].find_one({"_id": doc["_id"]})
    assert stored["last_used_at"] > stale.replace(tzinfo=None)


@pytest.mark.asyncio
async def test_touch_last_used_is_scoped_to_the_key():
    """Stamping a key that does not exist is the order-free half: an unfiltered write lands on
    whichever document happens to come first, so with no key addressed none may carry a stamp,
    whatever the insertion order. Asserting only that a sibling stayed null passes as soon as the
    addressed key is the first one."""
    db = FakeDatabase()
    repo = ApiKeyRepository(db)
    used, _ = await repo.create(_OWNER, _KEY_NAME, _BOTH_SURFACES, _EXPIRY_DAYS)
    untouched, _ = await repo.create(_OWNER, _OTHER_KEY_NAME, _BOTH_SURFACES, _EXPIRY_DAYS)

    await repo.touch_last_used(_MISSING_KEY_ID)

    assert (await db[_COL].find_one({"_id": used["_id"]}))["last_used_at"] is None
    assert (await db[_COL].find_one({"_id": untouched["_id"]}))["last_used_at"] is None

    await repo.touch_last_used(used["_id"])

    assert (await db[_COL].find_one({"_id": used["_id"]}))["last_used_at"] is not None
    assert (await db[_COL].find_one({"_id": untouched["_id"]}))["last_used_at"] is None
