"""renew_lock extends only the caller's own lock, so a holder learns when another one took its expired lock over."""

import asyncio
import contextlib
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock

import pytest
from pymongo.errors import AutoReconnect

from app.repositories.distributed_locks import DistributedLocksRepository, run_holding_lock
from tests.mocks.fake_mongo import FakeDatabase


@pytest.mark.asyncio
async def test_renew_extends_the_holders_lock():
    db = FakeDatabase()
    repo = DistributedLocksRepository(db)
    assert await repo.acquire_lock("lock-x", "pod-a", ttl_seconds=30)

    assert await repo.renew_lock("lock-x", "pod-a", ttl_seconds=600) is True

    lock = await db.distributed_locks.find_one({"_id": "lock-x"})
    assert lock["expires_at"] > datetime.now(timezone.utc) + timedelta(seconds=500)
    assert lock["holder"] == "pod-a"


@pytest.mark.asyncio
async def test_renew_refuses_a_lock_another_holder_took_over():
    db = FakeDatabase()
    expires_at = datetime.now(timezone.utc) + timedelta(seconds=30)
    await db.distributed_locks.insert_one({"_id": "lock-x", "holder": "pod-b", "expires_at": expires_at})

    assert await DistributedLocksRepository(db).renew_lock("lock-x", "pod-a", ttl_seconds=600) is False

    lock = await db.distributed_locks.find_one({"_id": "lock-x"})
    assert lock["holder"] == "pod-b"
    assert lock["expires_at"] < datetime.now(timezone.utc) + timedelta(seconds=60)


@pytest.mark.asyncio
async def test_renew_refuses_a_released_lock():
    db = FakeDatabase()

    assert await DistributedLocksRepository(db).renew_lock("lock-x", "pod-a", ttl_seconds=600) is False

    assert await db.distributed_locks.find_one({"_id": "lock-x"}) is None


@pytest.mark.asyncio
async def test_a_failed_renewal_is_retried_on_the_next_tick():
    renew = AsyncMock(side_effect=[AutoReconnect("primary stepped down"), True, True, True, True, True])

    result = await run_holding_lock(renew, 0.3, asyncio.sleep(0.35, result="done"))

    assert result == "done"
    assert renew.await_count >= 2


@pytest.mark.asyncio
async def test_work_that_finishes_despite_a_lost_lock_keeps_its_result():
    async def swallow_one_cancel() -> str:
        with contextlib.suppress(asyncio.CancelledError):
            await asyncio.sleep(1)
        return "done"

    assert await run_holding_lock(AsyncMock(return_value=False), 0.3, swallow_one_cancel()) == "done"
