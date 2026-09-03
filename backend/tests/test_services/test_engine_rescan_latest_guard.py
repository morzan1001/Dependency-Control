"""A rescan carries created_at = now, so without a lineage guard it always wins the latest-scan slot."""

from datetime import datetime, timedelta, timezone

import pytest

from app.repositories import ProjectRepository, ScanRepository
from app.services.analysis.engine import _should_update_project_latest_scan
from tests.mocks.fake_mongo import FakeDatabase

_NOW = datetime(2026, 9, 1, tzinfo=timezone.utc)


class _ScanDoc:
    def __init__(self, created_at, is_rescan=False, original_scan_id=None):
        self.created_at = created_at
        self.is_rescan = is_rescan
        self.original_scan_id = original_scan_id


@pytest.fixture
def db():
    return FakeDatabase()


async def _seed(db, latest_scan_id):
    await db.projects.insert_one({"_id": "p1", "name": "proj", "latest_scan_id": latest_scan_id})
    await db.scans.insert_one(
        {"_id": "head", "project_id": "p1", "branch": "main", "status": "completed", "created_at": _NOW}
    )
    await db.scans.insert_one(
        {
            "_id": "release",
            "project_id": "p1",
            "branch": "main",
            "status": "completed",
            "created_at": _NOW - timedelta(days=30),
        }
    )


@pytest.mark.asyncio
async def test_a_rescan_of_the_current_latest_still_updates_it(db):
    await _seed(db, "head")
    scan_doc = _ScanDoc(_NOW + timedelta(hours=1), is_rescan=True, original_scan_id="head")

    assert await _should_update_project_latest_scan(
        "rescan-1", scan_doc, "p1", ScanRepository(db), ProjectRepository(db)
    ) is True


@pytest.mark.asyncio
async def test_a_rescan_of_the_release_does_not_hijack_the_project_tile(db):
    await _seed(db, "head")
    scan_doc = _ScanDoc(_NOW + timedelta(hours=1), is_rescan=True, original_scan_id="release")

    assert await _should_update_project_latest_scan(
        "rescan-2", scan_doc, "p1", ScanRepository(db), ProjectRepository(db)
    ) is False


@pytest.mark.asyncio
async def test_a_manual_rescan_of_an_old_scan_does_not_hijack_it_either(db):
    await _seed(db, "head")
    scan_doc = _ScanDoc(_NOW + timedelta(days=2), is_rescan=True, original_scan_id="release")

    assert await _should_update_project_latest_scan(
        "rescan-3", scan_doc, "p1", ScanRepository(db), ProjectRepository(db)
    ) is False


@pytest.mark.asyncio
async def test_a_fresh_ingest_still_wins_the_slot(db):
    await _seed(db, "release")
    scan_doc = _ScanDoc(_NOW + timedelta(hours=1))

    assert await _should_update_project_latest_scan(
        "head", scan_doc, "p1", ScanRepository(db), ProjectRepository(db)
    ) is True


@pytest.mark.asyncio
async def test_a_rescan_is_still_accepted_when_the_project_has_no_latest_scan(db):
    await db.projects.insert_one({"_id": "p1", "name": "proj", "latest_scan_id": None})
    scan_doc = _ScanDoc(_NOW, is_rescan=True, original_scan_id="gone")

    assert await _should_update_project_latest_scan(
        "rescan-4", scan_doc, "p1", ScanRepository(db), ProjectRepository(db)
    ) is True
