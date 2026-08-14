"""completed_with_errors scans must stay visible to every latest-scan consumer."""

from datetime import datetime, timedelta, timezone

import pytest

from app.repositories.scans import ScanRepository
from tests.mocks.fake_mongo import FakeDatabase

_NOW = datetime.now(timezone.utc)


@pytest.fixture
def db():
    return FakeDatabase()


async def _seed_scans(db):
    await db.scans.insert_one(
        {
            "_id": "scan-old-completed",
            "project_id": "p1",
            "branch": "main",
            "status": "completed",
            "created_at": _NOW - timedelta(days=2),
        }
    )
    await db.scans.insert_one(
        {
            "_id": "scan-new-partial",
            "project_id": "p1",
            "branch": "main",
            "status": "completed_with_errors",
            "created_at": _NOW - timedelta(hours=1),
        }
    )


@pytest.mark.asyncio
async def test_get_latest_active_scan_includes_completed_with_errors(db):
    await _seed_scans(db)
    scan = await ScanRepository(db).get_latest_active_scan({"_id": "p1", "deleted_branches": []})
    assert scan is not None
    assert scan.id == "scan-new-partial", "a partially-failed scan must not silently drop out of the latest view"


@pytest.mark.asyncio
async def test_get_latest_active_scan_ids_includes_completed_with_errors(db):
    await _seed_scans(db)
    result = await ScanRepository(db).get_latest_active_scan_ids(
        [{"_id": "p1", "deleted_branches": ["gone"], "latest_scan_id": "scan-old-completed"}]
    )
    assert result == {"p1": "scan-new-partial"}


@pytest.mark.asyncio
async def test_get_latest_for_project_usable_statuses(db):
    await _seed_scans(db)
    from app.core.constants import SCAN_USABLE_STATUSES

    scan = await ScanRepository(db).get_latest_for_project("p1", statuses=SCAN_USABLE_STATUSES)
    assert scan is not None
    assert scan.id == "scan-new-partial"
