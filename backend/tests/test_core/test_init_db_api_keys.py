"""create_indexes must build the unified api_keys collection indexes."""

import asyncio
from unittest.mock import AsyncMock

import pymongo

from app.core.init_db import create_indexes
from tests.mocks.fake_mongo import FakeDatabase


def test_api_key_indexes_cover_listing_lookup_and_expiry():
    """The unique token lookup is the one that stops a duplicate key ever being stored, and the
    name alone does not say which field it covers."""
    db = FakeDatabase()
    db.api_keys.create_index = AsyncMock()

    asyncio.run(create_indexes(db))

    calls = {call.kwargs["name"]: (call.args[0], call.kwargs) for call in db.api_keys.create_index.await_args_list}
    assert calls["api_keys_user_listing"][0] == [("user_id", pymongo.ASCENDING), ("created_at", pymongo.DESCENDING)]
    assert calls["api_keys_token_lookup"][0] == [("token_hash", pymongo.ASCENDING)]
    assert calls["api_keys_token_lookup"][1]["unique"] is True
    assert calls["api_keys_ttl"][0] == [("expires_at", pymongo.ASCENDING)]
    assert calls["api_keys_ttl"][1]["expireAfterSeconds"] == 0
