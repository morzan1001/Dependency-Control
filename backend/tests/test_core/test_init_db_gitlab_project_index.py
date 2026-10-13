"""A GitLab project links to one project per instance, whatever numeric type stored its id."""

import asyncio
import logging

import pymongo

from app.core.init_db import create_indexes
from tests.mocks.fake_mongo import FakeDatabase

_KEY = [("gitlab_instance_id", pymongo.ASCENDING), ("gitlab_project_id", pymongo.ASCENDING)]
_INDEX_NAME = "projects_gitlab_key"


def _gitlab_key_calls(failure: Exception | None = None) -> list[dict]:
    db = FakeDatabase()
    collection = db["projects"]
    build_index = collection.create_index
    calls: list[dict] = []

    async def _create_index(keys, **kwargs):
        if keys == _KEY:
            calls.append(kwargs)
            if failure is not None:
                raise failure
        return await build_index(keys, **kwargs)

    collection.create_index = _create_index
    asyncio.run(create_indexes(db))
    return calls


def test_the_key_is_unique_over_every_numeric_type():
    """$type "number" keeps int32, int64 and double ids under one constraint."""
    (options,) = _gitlab_key_calls()

    assert options["unique"] is True
    assert options["name"] == _INDEX_NAME
    assert options["partialFilterExpression"] == {
        "gitlab_instance_id": {"$type": "string"},
        "gitlab_project_id": {"$type": "number"},
    }


def test_a_duplicate_key_is_logged_and_startup_continues(caplog):
    duplicate = pymongo.errors.DuplicateKeyError(
        "E11000 duplicate key error",
        11000,
        {"code": 11000, "codeName": "DuplicateKey", "keyValue": {"gitlab_instance_id": "gl-1", "gitlab_project_id": 7}},
    )

    with caplog.at_level(logging.ERROR, logger="app.core.init_db"):
        _gitlab_key_calls(duplicate)

    record = next(record for record in caplog.records if _INDEX_NAME in record.getMessage())
    assert record.args[1] == "DuplicateKey"
    assert "'gitlab_project_id': 7" in record.getMessage()
