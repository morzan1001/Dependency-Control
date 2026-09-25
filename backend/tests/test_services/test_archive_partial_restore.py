"""A restore counts as finished only once every write landed; the reaper must never take a partial one for done."""

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch

import pytest
from pymongo.errors import AutoReconnect

from app.core.constants import SCAN_SCOPED_COLLECTIONS
from app.core.housekeeping import _reap_stale_metadata
from app.repositories.archive_metadata import ArchiveMetadataRepository
from app.services.archive import archive_scan, restore_scan
from tests.mocks.fake_mongo import FakeDatabase

MODULE = "app.services.archive"
SCAN_ID = "scan-1"
_ARCHIVED_AT = datetime(2026, 9, 1, 12, 0, tzinfo=timezone.utc)


@pytest.fixture
def archive_env(monkeypatch):
    from tests.helpers.fake_s3 import FakeS3Client, fake_get_s3_client

    fake = FakeS3Client()
    monkeypatch.setattr("app.core.s3.get_s3_client", lambda: fake_get_s3_client(fake))
    monkeypatch.setattr("app.core.s3.is_archive_enabled", lambda: True)
    monkeypatch.setattr(f"{MODULE}.is_archive_enabled", lambda: True)
    monkeypatch.setattr(f"{MODULE}.is_encryption_enabled", lambda: False)

    class _S:
        S3_BUCKET_NAME = "test-bucket"

    monkeypatch.setattr("app.core.s3.settings", _S)
    return fake


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
    assert scan["restored_at"] > _ARCHIVED_AT.replace(tzinfo=None)
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
