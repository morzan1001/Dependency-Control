"""Lock-state reads must hit Primary so two pods never both observe 'free'."""

import asyncio
from unittest.mock import MagicMock

from pymongo import ReadPreference

from app.repositories.distributed_locks import DistributedLocksRepository


class _AsyncCursor:
    def __init__(self, docs):
        self._docs = iter(docs)

    def __aiter__(self):
        return self

    async def __anext__(self):
        try:
            return next(self._docs)
        except StopIteration:
            raise StopAsyncIteration from None


class TestLockReadsArePinnedToPrimary:
    def test_held_locks_uses_primary_pinned_collection(self):
        primary = MagicMock()
        primary.find = MagicMock(return_value=_AsyncCursor([{"_id": "lock-1"}]))
        base = MagicMock()
        base.with_options = MagicMock(return_value=primary)
        db = MagicMock()
        db.distributed_locks = base

        repo = DistributedLocksRepository(db)
        base.with_options.assert_called_once_with(read_preference=ReadPreference.PRIMARY)

        assert asyncio.run(repo.held_locks(["lock-1"])) == {"lock-1"}
        base.find.assert_not_called()
