"""Distributed locks: a held lock is refused, only its holder releases or renews it, and only unexpired locks count."""

import asyncio
import contextlib
import os
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock

import pytest
from pymongo.errors import AutoReconnect

from app.core.constants import INSTANCE_ID
from app.repositories.distributed_locks import DistributedLocksRepository, new_lock_holder, run_holding_lock
from tests.mocks.fake_mongo import FakeDatabase


@pytest.mark.asyncio
async def test_returns_false_instead_of_raising_when_lock_held():
    repo = DistributedLocksRepository(FakeDatabase())
    assert await repo.acquire_lock("lock-a", "A", ttl_seconds=300) is True

    assert await repo.acquire_lock("lock-a", "B", ttl_seconds=300) is False


@pytest.mark.asyncio
async def test_expired_lock_can_be_taken_over():
    db = FakeDatabase()
    repo = DistributedLocksRepository(db)
    assert await repo.acquire_lock("lock-b", "A", ttl_seconds=300) is True
    db.distributed_locks._docs["lock-b"]["expires_at"] = datetime(2000, 1, 1, tzinfo=timezone.utc)

    assert await repo.acquire_lock("lock-b", "B", ttl_seconds=300) is True


@pytest.mark.asyncio
async def test_non_holder_cannot_release_anothers_lock():
    repo = DistributedLocksRepository(FakeDatabase())
    assert await repo.acquire_lock("lock-x", "A", ttl_seconds=300) is True

    assert await repo.release_lock("lock-x", "B") is False
    assert await repo.acquire_lock("lock-x", "C", ttl_seconds=300) is False


@pytest.mark.asyncio
async def test_holder_can_release_own_lock():
    repo = DistributedLocksRepository(FakeDatabase())
    assert await repo.acquire_lock("lock-y", "A", ttl_seconds=300) is True

    assert await repo.release_lock("lock-y", "A") is True
    assert await repo.acquire_lock("lock-y", "B", ttl_seconds=300) is True


def test_every_acquisition_gets_its_own_holder_carrying_the_process():
    """Several processes share one host's HOSTNAME; a holder built from it alone lets one
    process release the lock another took over after the TTL."""
    first, second = new_lock_holder(), new_lock_holder()

    assert first != second
    assert f"{os.getenv('HOSTNAME', 'unknown')}:{os.getpid()}" == INSTANCE_ID
    assert first.startswith(f"{INSTANCE_ID}:") and second.startswith(f"{INSTANCE_ID}:")


@pytest.mark.asyncio
async def test_held_locks_reports_only_unexpired_locks():
    now = datetime.now(timezone.utc)
    db = FakeDatabase()
    await db.distributed_locks.insert_many(
        [
            {"_id": "lock-held", "holder": "pod-a", "expires_at": now + timedelta(minutes=5)},
            {"_id": "lock-expired", "holder": "pod-b", "expires_at": now - timedelta(minutes=5)},
            {"_id": "lock-other", "holder": "pod-c", "expires_at": now + timedelta(minutes=5)},
        ]
    )

    held = await DistributedLocksRepository(db).held_locks(["lock-held", "lock-expired", "lock-absent"])

    assert held == {"lock-held"}


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
