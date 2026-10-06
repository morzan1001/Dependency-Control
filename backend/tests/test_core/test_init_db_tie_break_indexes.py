"""A date-ordered pick tie-breaks on _id; without _id in the index the pick becomes a blocking sort."""

import asyncio
from unittest.mock import AsyncMock

import pymongo

from app.core.constants import SCANS_TIP_SORT
from app.core.init_db import (
    RELEASES_LATEST_LOOKUP_KEY,
    RELEASES_LATEST_LOOKUP_NAME,
    RELEASES_LATEST_SORT,
    SCANS_TIP_INDEX_KEY,
    create_indexes,
)
from tests.mocks.fake_mongo import FakeDatabase

_SCANS = "scans"
_RELEASES = "releases"
_TIE_BREAK = ("_id", pymongo.ASCENDING)
_EXPECTED_MATCHES = 1


def _index_calls(collection_name: str) -> list:
    db = FakeDatabase()
    collection = db[collection_name]
    collection.create_index = AsyncMock()
    asyncio.run(create_indexes(db))
    return list(collection.create_index.await_args_list)


def test_the_rescan_tip_index_carries_the_tie_break_key():
    calls = _index_calls(_SCANS)
    matching = [call for call in calls if call.args and call.args[0] == SCANS_TIP_INDEX_KEY]
    assert len(matching) == _EXPECTED_MATCHES
    assert SCANS_TIP_INDEX_KEY[-1] == _TIE_BREAK


def test_the_latest_release_index_carries_the_tie_break_key():
    calls = _index_calls(_RELEASES)
    matching = [
        call
        for call in calls
        if call.kwargs.get("name") == RELEASES_LATEST_LOOKUP_NAME and call.args[0] == RELEASES_LATEST_LOOKUP_KEY
    ]
    assert len(matching) == _EXPECTED_MATCHES
    assert RELEASES_LATEST_LOOKUP_KEY[-1] == _TIE_BREAK


def test_each_tie_break_sort_is_the_trailing_keys_of_its_index():
    """The sort the query issues has to be an index suffix, or the equality prefix buys nothing."""
    assert SCANS_TIP_INDEX_KEY[-len(SCANS_TIP_SORT) :] == SCANS_TIP_SORT
    assert RELEASES_LATEST_LOOKUP_KEY[-len(RELEASES_LATEST_SORT) :] == RELEASES_LATEST_SORT
