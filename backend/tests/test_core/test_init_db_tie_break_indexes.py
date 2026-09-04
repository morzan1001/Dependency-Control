"""A date-ordered pick tie-breaks on _id; without _id in the index the pick becomes a blocking sort."""

import asyncio
from unittest.mock import AsyncMock

import pymongo

from app.core.init_db import (
    RELEASES_LATEST_LOOKUP_KEY,
    RELEASES_LATEST_LOOKUP_NAME,
    RELEASES_LATEST_SORT,
    SCANS_TIP_INDEX_KEY,
    SCANS_TIP_SORT,
    create_indexes,
)
from tests.mocks.fake_mongo import FakeDatabase

_SCANS = "scans"
_RELEASES = "releases"
_TIE_BREAK = ("_id", pymongo.ASCENDING)
_EXPECTED_MATCHES = 1


def _index_calls(collection_name: str, existing: dict | None = None) -> tuple[list, AsyncMock]:
    db = FakeDatabase()
    collection = db[collection_name]
    collection.create_index = AsyncMock()
    collection.drop_index = AsyncMock()
    if existing is not None:
        collection.index_information = AsyncMock(return_value=existing)
    asyncio.run(create_indexes(db))
    return list(collection.create_index.await_args_list), collection.drop_index


def test_the_rescan_tip_index_carries_the_tie_break_key():
    calls, _ = _index_calls(_SCANS)
    matching = [call for call in calls if call.args and call.args[0] == SCANS_TIP_INDEX_KEY]
    assert len(matching) == _EXPECTED_MATCHES
    assert SCANS_TIP_INDEX_KEY[-1] == _TIE_BREAK


def test_the_latest_release_index_carries_the_tie_break_key():
    calls, _ = _index_calls(_RELEASES)
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


def test_the_date_only_ancestor_index_is_dropped():
    """Left in place it is a second index every write maintains for no plan the new one lacks."""
    ancestor = [pair for pair in SCANS_TIP_INDEX_KEY if pair != _TIE_BREAK]
    ancestor_name = "project_id_1_status_1_created_at_-1"
    _, drop_index = _index_calls(_SCANS, existing={ancestor_name: {"key": ancestor}})
    drop_index.assert_awaited_once_with(ancestor_name)


def test_an_unrelated_index_survives_the_migration():
    _, drop_index = _index_calls(_SCANS, existing={"original_scan_id_1": {"key": [("original_scan_id", 1)]}})
    drop_index.assert_not_awaited()
