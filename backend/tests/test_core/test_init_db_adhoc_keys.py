"""create_indexes must build the ad-hoc key indexes on the adhoc_api_keys collection."""

import asyncio
from unittest.mock import AsyncMock

from app.core.init_db import create_indexes
from tests.mocks.fake_mongo import FakeDatabase

_COL = "adhoc_api_keys"
_EXPECTED_INDEX_NAMES = ["adhoc_keys_user_listing", "adhoc_keys_token_lookup", "adhoc_keys_ttl"]
_LOOKUP_CALL = 1
_TTL_CALL = 2
_TTL_EXPIRE_AFTER_SECONDS = 0


def test_adhoc_key_indexes_target_adhoc_api_keys_collection():
    db = FakeDatabase()
    real = db[_COL]
    real.create_index = AsyncMock()

    asyncio.run(create_indexes(db))

    assert real.create_index.await_count == len(_EXPECTED_INDEX_NAMES)
    names = [call.kwargs.get("name") for call in real.create_index.await_args_list]
    assert names == _EXPECTED_INDEX_NAMES
    assert real.create_index.await_args_list[_LOOKUP_CALL].kwargs.get("unique") is True
    assert real.create_index.await_args_list[_TTL_CALL].kwargs.get("expireAfterSeconds") == _TTL_EXPIRE_AFTER_SECONDS
