"""The delivery log keeps only the indexes a read or the TTL uses: every insert maintains each one."""

import asyncio
from unittest.mock import AsyncMock

import pymongo

from app.core.init_db import create_indexes
from tests.mocks.fake_mongo import FakeDatabase


def test_only_the_chat_lookup_and_the_ttl_are_indexed():
    db = FakeDatabase()
    db["webhook_deliveries"].create_index = AsyncMock()

    asyncio.run(create_indexes(db))

    keys = [call.args[0] for call in db["webhook_deliveries"].create_index.await_args_list]
    assert keys == [
        [("webhook_id", pymongo.ASCENDING), ("timestamp", pymongo.DESCENDING)],
        [("timestamp", pymongo.ASCENDING)],
    ]
