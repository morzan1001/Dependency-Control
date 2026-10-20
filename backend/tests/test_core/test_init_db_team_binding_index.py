import asyncio
import logging
from unittest.mock import AsyncMock

import pymongo

from app.core.init_db import create_indexes
from app.repositories.teams import BINDING_KEY_PATH
from tests.mocks.fake_mongo import FakeDatabase

_KEY = [(BINDING_KEY_PATH, pymongo.ASCENDING)]


def _binding_index_calls() -> list:
    db = FakeDatabase()
    collection = db["teams"]
    collection.create_index = AsyncMock()
    asyncio.run(create_indexes(db))
    return [call for call in collection.create_index.await_args_list if call.args and call.args[0] == _KEY]


def test_the_binding_key_is_unique():
    calls = _binding_index_calls()
    assert len(calls) == 1, f"exactly one {BINDING_KEY_PATH} index expected"
    assert calls[0].kwargs["unique"] is True


def test_teams_holding_no_binding_stay_outside_the_unique_scope():
    """A unique index keys a missing array path as null, so without the filter a second unbound team collides."""
    assert _binding_index_calls()[0].kwargs["partialFilterExpression"] == {BINDING_KEY_PATH: {"$type": "string"}}


def _skip_record(failure: Exception, caplog) -> logging.LogRecord:
    db = FakeDatabase()
    collection = db["teams"]
    build_index = collection.create_index

    async def _create_index(keys, **kwargs):
        if keys == _KEY:
            raise failure
        return await build_index(keys, **kwargs)

    collection.create_index = _create_index
    with caplog.at_level(logging.ERROR, logger="app.core.init_db"):
        asyncio.run(create_indexes(db))

    return next(record for record in caplog.records if BINDING_KEY_PATH in record.getMessage())


def test_an_options_conflict_is_named_rather_than_blamed_on_a_duplicate(caplog):
    """An operator sent after a duplicate that does not exist leaves the wrong index in place."""
    record = _skip_record(
        pymongo.errors.OperationFailure(
            "Index already exists with a different name: teams_binding_key",
            85,
            {"ok": 0.0, "code": 85, "codeName": "IndexOptionsConflict"},
        ),
        caplog,
    )

    assert record.args[1] == "IndexOptionsConflict"
    assert "duplicate" not in record.getMessage().lower()


def test_a_real_duplicate_is_named_and_carries_the_offending_key(caplog):
    record = _skip_record(
        pymongo.errors.DuplicateKeyError(
            "E11000 duplicate key error",
            11000,
            {"code": 11000, "codeName": "DuplicateKey", "keyValue": {BINDING_KEY_PATH: "github:gh-1:4711"}},
        ),
        caplog,
    )

    assert record.args[1] == "DuplicateKey"
    assert "github:gh-1:4711" in record.getMessage()
