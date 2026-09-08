"""A GitHub-synced team is identified by (instance, numeric team id) and must be unique."""

import asyncio
from unittest.mock import AsyncMock

import pymongo

from app.core.init_db import create_indexes
from tests.mocks.fake_mongo import FakeDatabase

_KEY = [("github_instance_id", pymongo.ASCENDING), ("github_team_id", pymongo.ASCENDING)]


def _github_team_index_calls() -> list:
    db = FakeDatabase()
    collection = db["teams"]
    collection.create_index = AsyncMock()
    asyncio.run(create_indexes(db))
    return [call for call in collection.create_index.await_args_list if call.args and call.args[0] == _KEY]


def test_the_github_team_key_is_unique():
    calls = _github_team_index_calls()
    assert len(calls) == 1, "exactly one (github_instance_id, github_team_id) index expected"
    assert calls[0].kwargs["unique"] is True


def test_manual_teams_stay_outside_the_unique_scope():
    """Pydantic writes github_team_id: null on every manual team, and an $exists filter matches
    an explicit null — the second manual team would be a duplicate key."""
    calls = _github_team_index_calls()
    assert calls[0].kwargs["partialFilterExpression"] == {
        "github_instance_id": {"$type": "string"},
        "github_team_id": {"$type": "number"},
    }


def test_the_scope_covers_team_ids_wider_than_int32():
    """pymongo encodes an id >= 2**31 as BSON long; "int" is int32 only and would exempt it."""
    assert _github_team_index_calls()[0].kwargs["partialFilterExpression"]["github_team_id"] != {"$type": "int"}
