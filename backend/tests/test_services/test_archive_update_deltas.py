"""Archive round-trip: restoring a scan must rebuild its update-frequency delta and re-point the successor."""

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch

import pytest

from app.core.housekeeping import _delete_scans_and_related_data
from app.services.archive import archive_scan, restore_scan
from app.services.update_frequency_rollup import record_scan_update_delta
from tests.mocks.fake_mongo import FakeDatabase

MODULE = "app.services.archive"
PROJECT = "proj-1"
T0 = datetime(2026, 6, 1, 12, 0, tzinfo=timezone.utc)


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


async def _seed_scan(db: FakeDatabase, scan_id: str, created_at: datetime, version: str) -> None:
    await db.scans.insert_one(
        {
            "_id": scan_id,
            "project_id": PROJECT,
            "branch": "main",
            "commit_hash": f"c-{scan_id}",
            "created_at": created_at,
            "status": "completed",
            "is_rescan": False,
            "sbom_refs": [],
        }
    )
    await db.dependencies.insert_one(
        {
            "_id": f"{scan_id}:requests",
            "scan_id": scan_id,
            "project_id": PROJECT,
            "name": "requests",
            "version": version,
            "type": "library",
            "purl": f"pkg:pypi/requests@{version}",
        }
    )
    await db.analysis_results.insert_one(
        {
            "_id": f"{scan_id}:outdated",
            "scan_id": scan_id,
            "analyzer_name": "outdated_packages",
            "result": {"outdated_dependencies": [{"component": "requests", "latest_version": "9.9.9"}]},
        }
    )


@pytest.mark.asyncio
async def test_restore_rebuilds_the_delta_and_repoints_the_successor(archive_env):
    db = FakeDatabase()
    await _seed_scan(db, "scan-1", T0, "2.31.0")
    await record_scan_update_delta(db, "scan-1")

    with (
        patch(f"{MODULE}.ArchiveMetadataRepository") as RepoCls,
        patch(f"{MODULE}.DistributedLocksRepository") as LockCls,
    ):
        RepoCls.return_value.find_by_scan_id = AsyncMock(return_value=None)
        RepoCls.return_value.create = AsyncMock()
        LockCls.return_value.acquire_lock = AsyncMock(return_value=True)
        LockCls.return_value.release_lock = AsyncMock(return_value=True)
        meta = await archive_scan(db, "scan-1")
    assert meta is not None

    with patch("app.services.gridfs_maintenance.AsyncIOMotorGridFSBucket", return_value=AsyncMock()):
        await _delete_scans_and_related_data(db, ["scan-1"])
    assert await db.scan_update_deltas.find_one({"_id": "scan-1"}) is None

    # The successor arrives while the predecessor is archived, so it can only be a baseline.
    await _seed_scan(db, "scan-2", T0 + timedelta(hours=6), "2.32.0")
    await record_scan_update_delta(db, "scan-2")
    assert (await db.scan_update_deltas.find_one({"_id": "scan-2"}))["is_baseline"] is True

    with (
        patch(f"{MODULE}.ArchiveMetadataRepository") as RepoCls,
        patch(f"{MODULE}.DistributedLocksRepository") as LockCls,
    ):
        RepoCls.return_value.find_by_scan_id = AsyncMock(return_value=meta)
        RepoCls.return_value.delete_by_scan_id = AsyncMock(return_value=True)
        LockCls.return_value.acquire_lock = AsyncMock(return_value=True)
        LockCls.return_value.release_lock = AsyncMock(return_value=True)
        result = await restore_scan(db, "scan-1")

    assert result is not None
    restored = await db.scan_update_deltas.find_one({"_id": "scan-1"})
    assert restored is not None, "the restored scan never got its delta back"
    assert restored["dep_count"] == 1
    assert await db.scan_outdated_sets.find_one({"_id": "scan-1"}) is not None

    successor = await db.scan_update_deltas.find_one({"_id": "scan-2"})
    assert successor["prev_scan_id"] == "scan-1", "the successor still points past the restored scan"
    assert successor["is_baseline"] is False
    assert successor["updates"]["minor"] == 1
