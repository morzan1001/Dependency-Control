"""Lock-state reads must hit Primary so two pods never both observe 'free'."""

import asyncio
from unittest.mock import MagicMock

from pymongo import ReadPreference

from app.repositories.distributed_locks import DistributedLocksRepository
from tests.mocks.mongodb import create_mock_collection


class TestLockReadsArePinnedToPrimary:
    def test_get_lock_info_uses_primary_pinned_collection(self):
        primary = create_mock_collection(find_one={"_id": "lock-1"})
        base = MagicMock()
        base.with_options = MagicMock(return_value=primary)
        db = MagicMock()
        db.distributed_locks = base

        repo = DistributedLocksRepository(db)
        base.with_options.assert_called_once_with(read_preference=ReadPreference.PRIMARY)

        asyncio.run(repo.get_lock_info("lock-1"))
        primary.find_one.assert_called_once_with({"_id": "lock-1"})

    def test_is_locked_uses_primary_pinned_collection(self):
        primary = create_mock_collection(find_one={"_id": "lock-1", "expires_at": "future"})
        base = MagicMock()
        base.with_options = MagicMock(return_value=primary)
        db = MagicMock()
        db.distributed_locks = base

        repo = DistributedLocksRepository(db)

        result = asyncio.run(repo.is_locked("lock-1"))
        assert result is True
        primary.find_one.assert_called_once()
