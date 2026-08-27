"""Retention must take the update-frequency rollups with it; they are keyed by scan id, not scan_id."""

from unittest.mock import AsyncMock, patch

import pytest

from app.core.housekeeping import _delete_scans_and_related_data
from tests.mocks.fake_mongo import FakeDatabase


async def _seed(db: FakeDatabase, scan_id: str) -> None:
    await db.scans.insert_one({"_id": scan_id, "project_id": "p1", "status": "completed", "sbom_refs": []})
    await db.scan_update_deltas.insert_one({"_id": scan_id, "project_id": "p1", "branch": "main", "dep_count": 3})
    await db.scan_outdated_sets.insert_one({"_id": scan_id, "names": ["flask"], "n": 1})


@pytest.mark.asyncio
async def test_retention_deletes_the_rollups_of_the_deleted_scans():
    db = FakeDatabase()
    await _seed(db, "scan-old")
    await _seed(db, "scan-kept")

    with patch("app.services.gridfs_maintenance.AsyncIOMotorGridFSBucket", return_value=AsyncMock()):
        deleted = await _delete_scans_and_related_data(db, ["scan-old"], "test")

    assert deleted == 1
    assert await db.scan_update_deltas.find_one({"_id": "scan-old"}) is None
    assert await db.scan_outdated_sets.find_one({"_id": "scan-old"}) is None
    assert await db.scan_update_deltas.find_one({"_id": "scan-kept"}) is not None
    assert await db.scan_outdated_sets.find_one({"_id": "scan-kept"}) is not None
