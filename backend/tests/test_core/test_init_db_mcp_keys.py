"""create_indexes must build the MCP key indexes on the mcp_api_keys collection."""

import asyncio
from unittest.mock import AsyncMock

from app.core.init_db import create_indexes
from tests.mocks.fake_mongo import FakeDatabase

_COL = "mcp_api_keys"
_EXPECTED_INDEX_NAMES = ["mcp_keys_user_listing", "mcp_keys_token_lookup", "mcp_keys_ttl"]
_LOOKUP_CALL = 1
_TTL_CALL = 2
_TTL_EXPIRE_AFTER_SECONDS = 0


def test_mcp_key_indexes_target_mcp_api_keys_collection():
    db = FakeDatabase()
    real = db[_COL]
    real.create_index = AsyncMock()

    asyncio.run(create_indexes(db))

    assert real.create_index.await_count == len(_EXPECTED_INDEX_NAMES)
    names = [call.kwargs.get("name") for call in real.create_index.await_args_list]
    assert names == _EXPECTED_INDEX_NAMES
    assert real.create_index.await_args_list[_LOOKUP_CALL].kwargs.get("unique") is True
    assert real.create_index.await_args_list[_TTL_CALL].kwargs.get("expireAfterSeconds") == _TTL_EXPIRE_AFTER_SECONDS
