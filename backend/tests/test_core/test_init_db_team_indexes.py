import asyncio

import pytest
from pymongo.errors import DuplicateKeyError, OperationFailure

from app.core.init_db import TEAM_BINDING_KEY_FIELD, create_indexes
from tests.mocks.fake_mongo import FakeDatabase


class TestTeamsUniqueIndexGuard:
    """create_indexes runs at pod startup, so a duplicate must not crash the pod into CrashLoopBackOff."""

    @staticmethod
    def _wrap_teams_index_to_raise(db, exc):
        teams = db["teams"]
        original_create_index = teams.create_index

        async def create_index(keys, **kwargs):
            if isinstance(keys, list) and [k[0] for k in keys] == [TEAM_BINDING_KEY_FIELD] and kwargs.get("unique"):
                raise exc
            return await original_create_index(keys, **kwargs)

        teams.create_index = create_index  # type: ignore[method-assign]

    def test_duplicate_key_error_does_not_propagate(self, caplog):
        db = FakeDatabase()
        self._wrap_teams_index_to_raise(
            db, DuplicateKeyError("E11000 duplicate key error", details={"keyValue": {"bindings.key": "gitlab:a:42"}})
        )

        with caplog.at_level("ERROR", logger="app.core.init_db"):
            asyncio.run(create_indexes(db))

        assert any("teams" in r.message.lower() or "index" in r.message.lower() for r in caplog.records), (
            f"Skipped teams unique index must be logged at ERROR. Got: {[r.message for r in caplog.records]}"
        )

    def test_operation_failure_does_not_propagate(self):
        db = FakeDatabase()
        self._wrap_teams_index_to_raise(db, OperationFailure("index build failed"))

        asyncio.run(create_indexes(db))

    def test_unrelated_index_failures_still_propagate(self):
        db = FakeDatabase()
        users = db["users"]

        async def failing_create_index(keys, **kwargs):
            raise OperationFailure("unrelated users index failure")

        users.create_index = failing_create_index  # type: ignore[method-assign]

        with pytest.raises(OperationFailure):
            asyncio.run(create_indexes(db))


class TestStartupBuildsTheBindingKey:
    """The live index tests build create_team_indexes, so startup must still call it for their proof to count."""

    def test_the_binding_key_gets_its_unique_index(self):
        db = FakeDatabase()

        asyncio.run(create_indexes(db))

        assert (TEAM_BINDING_KEY_FIELD,) in db["teams"].created_indexes
