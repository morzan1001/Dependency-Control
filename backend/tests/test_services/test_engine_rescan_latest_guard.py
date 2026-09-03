"""A rescan carries created_at = now, so without a lineage guard it always wins the latest-scan slot."""

from datetime import datetime, timedelta, timezone

import pytest

from app.core.constants import SCAN_STATUS_COMPLETED
from app.repositories import ProjectRepository, ScanRepository
from app.services.analysis.engine import _should_update_project_latest_scan
from tests.mocks.fake_mongo import FakeDatabase

_PROJECT_ID = "p1"
_PROJECT_NAME = "proj"
_MAIN_BRANCH = "main"

_HEAD_SCAN_ID = "head"
_RELEASE_SCAN_ID = "release"
_SCHEDULED_RESCAN_ID = "scheduled-rescan"
_MISSING_SCAN_ID = "gone"

_INCOMING_RESCAN_ID = "incoming-rescan"
_INCOMING_INGEST_ID = "incoming-ingest"

_NOW = datetime(2026, 9, 1, tzinfo=timezone.utc)
_LATER = timedelta(hours=1)
_RELEASE_AGE = timedelta(days=30)


class _ScanDoc:
    def __init__(self, created_at, is_rescan=False, original_scan_id=None):
        self.created_at = created_at
        self.is_rescan = is_rescan
        self.original_scan_id = original_scan_id


@pytest.fixture
def db():
    return FakeDatabase()


async def _insert_scan(db, scan_id, created_at, **overrides):
    doc = {
        "_id": scan_id,
        "project_id": _PROJECT_ID,
        "branch": _MAIN_BRANCH,
        "status": SCAN_STATUS_COMPLETED,
        "created_at": created_at,
    }
    doc.update(overrides)
    await db.scans.insert_one(doc)


async def _seed(db, latest_scan_id):
    await db.projects.insert_one({"_id": _PROJECT_ID, "name": _PROJECT_NAME, "latest_scan_id": latest_scan_id})
    await _insert_scan(db, _HEAD_SCAN_ID, _NOW)
    await _insert_scan(db, _RELEASE_SCAN_ID, _NOW - _RELEASE_AGE)


async def _decide(db, scan_id, scan_doc):
    return await _should_update_project_latest_scan(
        scan_id, scan_doc, _PROJECT_ID, ScanRepository(db), ProjectRepository(db)
    )


@pytest.mark.asyncio
async def test_a_rescan_of_the_current_latest_still_updates_it(db):
    await _seed(db, _HEAD_SCAN_ID)
    scan_doc = _ScanDoc(_NOW + _LATER, is_rescan=True, original_scan_id=_HEAD_SCAN_ID)

    assert await _decide(db, _INCOMING_RESCAN_ID, scan_doc) is True


@pytest.mark.asyncio
async def test_a_rescan_of_the_release_does_not_hijack_the_project_tile(db):
    await _seed(db, _HEAD_SCAN_ID)
    scan_doc = _ScanDoc(_NOW + _LATER, is_rescan=True, original_scan_id=_RELEASE_SCAN_ID)

    assert await _decide(db, _INCOMING_RESCAN_ID, scan_doc) is False


@pytest.mark.asyncio
async def test_a_manual_rescan_wins_the_slot_when_the_latest_is_a_scheduled_rescan_of_the_same_original(db):
    """Both sides reduce to their lineage root, so the manual endpoint's root-valued
    original_scan_id matches a latest that is itself a rescan."""
    await _seed(db, _SCHEDULED_RESCAN_ID)
    await _insert_scan(
        db, _SCHEDULED_RESCAN_ID, _NOW + _LATER, is_rescan=True, original_scan_id=_HEAD_SCAN_ID
    )
    scan_doc = _ScanDoc(_NOW + 2 * _LATER, is_rescan=True, original_scan_id=_HEAD_SCAN_ID)

    assert await _decide(db, _INCOMING_RESCAN_ID, scan_doc) is True


@pytest.mark.asyncio
async def test_a_rescan_with_no_recorded_lineage_is_judged_on_its_created_at_alone(db):
    await _seed(db, _RELEASE_SCAN_ID)
    scan_doc = _ScanDoc(_NOW + _LATER, is_rescan=True, original_scan_id=None)

    assert await _decide(db, _INCOMING_RESCAN_ID, scan_doc) is True


@pytest.mark.asyncio
async def test_a_fresh_ingest_wins_the_slot_even_when_it_carries_a_lineage_field(db):
    await _seed(db, _RELEASE_SCAN_ID)
    scan_doc = _ScanDoc(_NOW + _LATER, is_rescan=False, original_scan_id=_HEAD_SCAN_ID)

    assert await _decide(db, _INCOMING_INGEST_ID, scan_doc) is True


@pytest.mark.asyncio
async def test_a_rescan_is_still_accepted_when_the_project_has_no_latest_scan(db):
    await db.projects.insert_one({"_id": _PROJECT_ID, "name": _PROJECT_NAME, "latest_scan_id": None})
    scan_doc = _ScanDoc(_NOW, is_rescan=True, original_scan_id=_MISSING_SCAN_ID)

    assert await _decide(db, _INCOMING_RESCAN_ID, scan_doc) is True
