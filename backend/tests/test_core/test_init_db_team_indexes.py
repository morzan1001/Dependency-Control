"""The guard around the teams unique index build, and that startup still builds it."""

import asyncio

import pytest
from pymongo.errors import DuplicateKeyError, OperationFailure

from app.core.init_db import TEAM_BINDING_KEY_FIELD, create_indexes
from tests.mocks.fake_mongo import FakeDatabase


class TestTeamsUniqueIndexGuard:
    """The teams unique binding-key index build must degrade gracefully (log + skip) on a startup
    duplicate. create_indexes runs at pod startup; an unhandled failure from that one build would
    crash the pod into CrashLoopBackOff instead of continuing.
    """

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
            # Must complete without raising — graceful degradation, not CrashLoopBackOff.
            asyncio.run(create_indexes(db))

        assert any("teams" in r.message.lower() or "index" in r.message.lower() for r in caplog.records), (
            f"Skipped teams unique index must be logged at ERROR. Got: {[r.message for r in caplog.records]}"
        )

    def test_operation_failure_does_not_propagate(self):
        db = FakeDatabase()
        self._wrap_teams_index_to_raise(db, OperationFailure("index build failed"))

        # Must complete without raising.
        asyncio.run(create_indexes(db))

    def test_unrelated_index_failures_still_propagate(self):
        """The guard must be narrow: a failure on a DIFFERENT index must NOT be swallowed."""
        db = FakeDatabase()
        users = db["users"]

        async def failing_create_index(keys, **kwargs):
            raise OperationFailure("unrelated users index failure")

        users.create_index = failing_create_index  # type: ignore[method-assign]

        with pytest.raises(OperationFailure):
            asyncio.run(create_indexes(db))


class TestStartupBuildsTheBindingKey:
    """create_team_indexes is what the live index tests build; startup has to still call it,
    or the uniqueness those tests prove would never reach a deployed installation."""

    def test_the_binding_key_gets_its_unique_index(self):
        db = FakeDatabase()

        asyncio.run(create_indexes(db))

        assert (TEAM_BINDING_KEY_FIELD,) in db["teams"].created_indexes
