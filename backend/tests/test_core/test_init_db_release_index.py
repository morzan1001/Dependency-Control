"""Release lookups must be served by an index or every read scans a whole collection."""

import asyncio
from unittest.mock import AsyncMock

import pymongo

from app.core.init_db import create_indexes
from tests.mocks.fake_mongo import FakeDatabase

_SCANS = "scans"
_RELEASES = "releases"
_SCANS_INDEX_NAME = "scans_released_list"
_RELEASES_INDEX_NAME = "releases_latest_lookup"
_RELEASES_UNIQUE_INDEX_NAME = "releases_upsert_key"
_RELEASED_SCANS_ONLY = {"is_release": True}
_EXPECTED_MATCHES = 1


def _create_index_calls(collection_name: str) -> list:
    db = FakeDatabase()
    collection = db[collection_name]
    collection.create_index = AsyncMock()
    asyncio.run(create_indexes(db))
    return list(collection.create_index.await_args_list)


def _named(calls: list, name: str) -> list:
    return [call for call in calls if call.kwargs.get("name") == name]


def test_released_scans_filter_index_is_partial_and_ordered():
    calls = _named(_create_index_calls(_SCANS), _SCANS_INDEX_NAME)
    assert len(calls) == _EXPECTED_MATCHES, f"exactly one {_SCANS_INDEX_NAME} index expected"
    assert calls[0].args[0] == [
        ("project_id", pymongo.ASCENDING),
        ("is_release", pymongo.ASCENDING),
        ("created_at", pymongo.DESCENDING),
    ]
    assert calls[0].kwargs["partialFilterExpression"] == _RELEASED_SCANS_ONLY


def test_latest_release_per_environment_is_indexed():
    calls = _named(_create_index_calls(_RELEASES), _RELEASES_INDEX_NAME)
    assert len(calls) == _EXPECTED_MATCHES, f"exactly one {_RELEASES_INDEX_NAME} index expected"
    assert calls[0].args[0] == [
        ("project_id", pymongo.ASCENDING),
        ("environment", pymongo.ASCENDING),
        ("released_at", pymongo.DESCENDING),
        ("_id", pymongo.ASCENDING),
    ]


def test_the_upsert_key_is_unique():
    """Without it two concurrent marks of one (project, environment, scan) both insert."""
    calls = _named(_create_index_calls(_RELEASES), _RELEASES_UNIQUE_INDEX_NAME)
    assert len(calls) == _EXPECTED_MATCHES, f"exactly one {_RELEASES_UNIQUE_INDEX_NAME} index expected"
    assert calls[0].args[0] == [
        ("project_id", pymongo.ASCENDING),
        ("environment", pymongo.ASCENDING),
        ("scan_id", pymongo.ASCENDING),
    ]
    assert calls[0].kwargs["unique"] is True


def test_releases_are_indexed_by_scan():
    calls = _create_index_calls(_RELEASES)
    assert [call for call in calls if call.args and call.args[0] == "scan_id"]
