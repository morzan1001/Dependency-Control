"""A restore counts as finished only once every write landed while it still owned the scan's restore lock."""

import asyncio
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch

import pytest
from pymongo.errors import AutoReconnect

from app.core.constants import SCAN_SCOPED_COLLECTIONS
from app.core.housekeeping import _reap_stale_metadata
from app.repositories.archive_metadata import ArchiveMetadataRepository
from app.repositories.distributed_locks import DistributedLocksRepository
from app.repositories.distributed_locks import new_lock_holder
from app.services.archive import archive_scan, restore_scan
from tests.mocks.fake_mongo import FakeDatabase

MODULE = "app.services.archive"
SCAN_ID = "scan-1"
LOCK_NAME = f"restore:{SCAN_ID}"
_ARCHIVED_AT = datetime(2026, 9, 1, 12, 0, tzinfo=timezone.utc)


async def _archived_scan(db: FakeDatabase) -> None:
    """Archive a scan and drop it from MongoDB, as retention housekeeping does."""
    await db.scans.insert_one(
        {
            "_id": SCAN_ID,
            "project_id": "proj-1",
            "branch": "main",
            "created_at": _ARCHIVED_AT - timedelta(days=90),
            "status": "completed",
            "sbom_refs": [],
        }
    )
    await db.analysis_results.insert_one(
        {"_id": f"{SCAN_ID}:outdated", "scan_id": SCAN_ID, "analyzer_name": "outdated_packages", "result": {}}
    )
    await db.dependencies.insert_one({"_id": f"{SCAN_ID}:requests", "scan_id": SCAN_ID, "name": "requests"})
    assert await archive_scan(db, SCAN_ID) is not None
    # Stored datetimes are millisecond-truncated, so an archive and restore in one test could tie.
    await db.archive_metadata.update_one({"scan_id": SCAN_ID}, {"$set": {"archived_at": _ARCHIVED_AT}})
    await db.scans.delete_one({"_id": SCAN_ID})
    for coll in SCAN_SCOPED_COLLECTIONS:
        await getattr(db, coll).delete_many({"scan_id": SCAN_ID})


async def _restore_dying_after_the_header(db: FakeDatabase) -> None:
    """The analysis_results batch lands, the dependencies batch fails, and the rollback fails in the same outage."""
    outage = AutoReconnect("primary stepped down")
    with (
        patch.object(db.dependencies, "insert_many", AsyncMock(side_effect=outage)),
        patch.object(db.scans, "delete_one", AsyncMock(side_effect=outage)),
    ):
        assert await restore_scan(db, SCAN_ID) is None
    assert await db.scans.find_one({"_id": SCAN_ID}) is not None, "the rollback was meant to leave the scan behind"


async def _surviving_metadata(db: FakeDatabase) -> list[str]:
    return [meta["scan_id"] async for meta in db.archive_metadata.find({})]


@pytest.mark.asyncio
async def test_a_rollback_failing_midway_leaves_the_scan_marked_for_the_next_restore(archive_env):
    db = FakeDatabase()
    await _archived_scan(db)
    outage = AutoReconnect("primary stepped down")
    with (
        patch.object(db.dependencies, "insert_many", AsyncMock(side_effect=outage)),
        patch.object(db.dependencies, "delete_many", AsyncMock(side_effect=outage)),
    ):
        assert await restore_scan(db, SCAN_ID) is None

    assert (await db.scans.find_one({"_id": SCAN_ID}))["restore_in_progress"] is True
    assert await restore_scan(db, SCAN_ID) is not None


@pytest.mark.asyncio
async def test_reaper_keeps_the_metadata_of_a_restore_that_died_after_its_header(archive_env):
    db = FakeDatabase()
    await _archived_scan(db)
    await _restore_dying_after_the_header(db)

    reaped = await _reap_stale_metadata(db)

    assert reaped == 0
    assert await _surviving_metadata(db) == [SCAN_ID], "the bundle is the only complete copy of the scan"


@pytest.mark.asyncio
async def test_reaper_drops_the_metadata_of_a_completed_restore_whose_cleanup_failed(archive_env, monkeypatch):
    db = FakeDatabase()
    await _archived_scan(db)
    monkeypatch.setattr(
        ArchiveMetadataRepository, "delete_by_scan_id", AsyncMock(side_effect=AutoReconnect("primary stepped down"))
    )

    assert await restore_scan(db, SCAN_ID) is not None
    scan = await db.scans.find_one({"_id": SCAN_ID})
    assert scan["restored_at"] > _ARCHIVED_AT
    assert "restore_in_progress" not in scan

    reaped = await _reap_stale_metadata(db)

    assert reaped == 1
    assert await _surviving_metadata(db) == []


@pytest.mark.asyncio
async def test_a_retry_after_a_crashed_restore_restores_the_scan(archive_env):
    db = FakeDatabase()
    await _archived_scan(db)
    await _restore_dying_after_the_header(db)

    result = await restore_scan(db, SCAN_ID)

    assert result is not None
    scan = await db.scans.find_one({"_id": SCAN_ID})
    assert scan["restored_at"] is not None
    assert scan["pinned"] is True
    assert "restore_in_progress" not in scan
    assert [doc["_id"] async for doc in db.analysis_results.find({"scan_id": SCAN_ID})] == [f"{SCAN_ID}:outdated"]
    assert [doc["_id"] async for doc in db.dependencies.find({"scan_id": SCAN_ID})] == [f"{SCAN_ID}:requests"]
    assert await _surviving_metadata(db) == []
    assert archive_env.objects == {}


class _FirstDependenciesBatchStall:
    """Holds the first dependencies batch until released, the way a slow write keeps a big restore busy."""

    def __init__(self, db: FakeDatabase, fails_with: Exception | None = None):
        self._insert_many = db.dependencies.insert_many
        self._fails_with = fails_with
        self._calls = 0
        self.reached = asyncio.Event()
        self.release = asyncio.Event()

    async def __call__(self, docs, **kwargs):
        self._calls += 1
        if self._calls == 1:
            self.reached.set()
            await self.release.wait()
            if self._fails_with is not None:
                raise self._fails_with
        return await self._insert_many(docs, **kwargs)


async def _take_over_the_restore_lock(db: FakeDatabase) -> str:
    """Another restore on this pod takes the lock over, as it can once missed renewals let the lock expire."""
    expired = datetime.now(timezone.utc) - timedelta(seconds=1)
    await db.distributed_locks.update_one({"_id": LOCK_NAME}, {"$set": {"expires_at": expired}})
    taker = new_lock_holder()
    assert await DistributedLocksRepository(db).acquire_lock(LOCK_NAME, taker, ttl_seconds=600)
    return taker


async def _assert_the_archive_survived(db: FakeDatabase, s3) -> None:
    assert await _surviving_metadata(db) == [SCAN_ID]
    assert len(s3.objects) == 1


@pytest.mark.asyncio
async def test_a_restore_outliving_the_lock_ttl_keeps_a_retry_out(archive_env, monkeypatch):
    monkeypatch.setattr(f"{MODULE}._ARCHIVE_LOCK_TTL_SECONDS", 0.3)
    db = FakeDatabase()
    await _archived_scan(db)
    stall = _FirstDependenciesBatchStall(db)

    with patch.object(db.dependencies, "insert_many", stall):
        first = asyncio.create_task(restore_scan(db, SCAN_ID))
        await stall.reached.wait()
        await asyncio.sleep(0.9)
        retry = await restore_scan(db, SCAN_ID)
        stall.release.set()
        result = await first

    assert retry is None
    assert result is not None
    scan = await db.scans.find_one({"_id": SCAN_ID})
    assert scan["restored_at"] is not None
    assert "restore_in_progress" not in scan
    assert [doc["_id"] async for doc in db.dependencies.find({"scan_id": SCAN_ID})] == [f"{SCAN_ID}:requests"]
    assert await _surviving_metadata(db) == []


@pytest.mark.asyncio
async def test_a_restore_stops_writing_once_another_restore_took_its_lock_over(archive_env, monkeypatch):
    monkeypatch.setattr(f"{MODULE}._ARCHIVE_LOCK_TTL_SECONDS", 0.3)
    db = FakeDatabase()
    await _archived_scan(db)
    stall = _FirstDependenciesBatchStall(db)

    with patch.object(db.dependencies, "insert_many", stall):
        first = asyncio.create_task(restore_scan(db, SCAN_ID))
        await stall.reached.wait()
        taker = await _take_over_the_restore_lock(db)
        await asyncio.sleep(1.0)
        stall.release.set()
        result = await first

    assert result is None
    assert await db.dependencies.find_one({"scan_id": SCAN_ID}) is None
    assert (await db.scans.find_one({"_id": SCAN_ID}))["restore_in_progress"] is True
    await _assert_the_archive_survived(db, archive_env)
    assert (await db.distributed_locks.find_one({"_id": LOCK_NAME}))["holder"] == taker


@pytest.mark.asyncio
async def test_a_restore_that_lost_its_lock_before_completing_keeps_the_archive(archive_env):
    db = FakeDatabase()
    await _archived_scan(db)
    stall = _FirstDependenciesBatchStall(db)

    with patch.object(db.dependencies, "insert_many", stall), patch(f"{MODULE}._count_failure") as count_failure:
        first = asyncio.create_task(restore_scan(db, SCAN_ID))
        await stall.reached.wait()
        await _take_over_the_restore_lock(db)
        stall.release.set()
        result = await first

    assert result is None
    count_failure.assert_called_once_with("restore", "lock_held")
    scan = await db.scans.find_one({"_id": SCAN_ID})
    assert scan["restore_in_progress"] is True
    assert "restored_at" not in scan
    await _assert_the_archive_survived(db, archive_env)


@pytest.mark.asyncio
async def test_a_restore_whose_scan_vanished_keeps_the_archive(archive_env):
    db = FakeDatabase()
    await _archived_scan(db)
    stall = _FirstDependenciesBatchStall(db)

    with patch.object(db.dependencies, "insert_many", stall):
        first = asyncio.create_task(restore_scan(db, SCAN_ID))
        await stall.reached.wait()
        await db.scans.delete_one({"_id": SCAN_ID})
        stall.release.set()
        result = await first

    assert result is None
    assert await db.scans.find_one({"_id": SCAN_ID}) is None
    assert await db.dependencies.find_one({"scan_id": SCAN_ID}) is None
    assert await db.analysis_results.find_one({"scan_id": SCAN_ID}) is None
    await _assert_the_archive_survived(db, archive_env)


@pytest.mark.asyncio
async def test_cancelling_a_restore_propagates_and_frees_its_lock(archive_env):
    db = FakeDatabase()
    await _archived_scan(db)
    stall = _FirstDependenciesBatchStall(db)

    with patch.object(db.dependencies, "insert_many", stall):
        first = asyncio.create_task(restore_scan(db, SCAN_ID))
        await stall.reached.wait()
        first.cancel()
        with pytest.raises(asyncio.CancelledError):
            await first

    assert await db.distributed_locks.find_one({"_id": LOCK_NAME}) is None


@pytest.mark.asyncio
async def test_a_restore_failing_after_another_restore_completed_leaves_its_scan_alone(archive_env):
    db = FakeDatabase()
    await _archived_scan(db)
    stall = _FirstDependenciesBatchStall(db, fails_with=AutoReconnect("connection reset once the partition healed"))

    with patch.object(db.dependencies, "insert_many", stall):
        first = asyncio.create_task(restore_scan(db, SCAN_ID))
        await stall.reached.wait()
        expired = datetime.now(timezone.utc) - timedelta(seconds=1)
        await db.distributed_locks.update_one({"_id": LOCK_NAME}, {"$set": {"expires_at": expired}})
        second = await restore_scan(db, SCAN_ID)
        stall.release.set()
        result = await first

    assert second is not None
    assert result is None
    scan = await db.scans.find_one({"_id": SCAN_ID})
    assert scan["restored_at"] is not None
    assert "restore_in_progress" not in scan
    assert [doc["_id"] async for doc in db.dependencies.find({"scan_id": SCAN_ID})] == [f"{SCAN_ID}:requests"]
    assert [doc["_id"] async for doc in db.analysis_results.find({"scan_id": SCAN_ID})] == [f"{SCAN_ID}:outdated"]
