"""The release lookup index must exist as a partial index or the resolver scans every scan."""

import asyncio
from unittest.mock import AsyncMock

import pymongo

from app.core.init_db import create_indexes
from tests.mocks.fake_mongo import FakeDatabase


def test_release_lookup_index_is_partial_and_ordered():
    db = FakeDatabase()
    scans = db["scans"]
    scans.create_index = AsyncMock()

    asyncio.run(create_indexes(db))

    calls = [c for c in scans.create_index.await_args_list if c.kwargs.get("name") == "scans_release_lookup"]
    assert len(calls) == 1, "exactly one scans_release_lookup index expected"
    keys = calls[0].args[0]
    assert keys == [
        ("project_id", pymongo.ASCENDING),
        ("release_environment", pymongo.ASCENDING),
        ("released_at", pymongo.DESCENDING),
    ]
    assert calls[0].kwargs["partialFilterExpression"] == {"is_release": True}
