"""What retention does to the update-frequency rollups, and what the reconcile makes of it."""

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch

import pytest

from app.core.housekeeping import _delete_scans_and_related_data
from app.core.metrics import update_frequency_reconcile_drift_total
from app.services.update_frequency_reconcile import run_update_frequency_reconcile
from app.services.update_frequency_rollup import record_scan_update_delta
from tests.mocks.fake_mongo import FakeDatabase

PROJECT = "p1"
BRANCH = "main"
# Relative to now: the reconcile only looks at a rolling window.
T0 = datetime.now(tz=timezone.utc) - timedelta(days=10)


def _severed_metric() -> float:
    return update_frequency_reconcile_drift_total.labels(kind="severed", outcome="resolved")._value.get()


async def _seed(db: FakeDatabase, scan_id: str) -> None:
    await db.scans.insert_one({"_id": scan_id, "project_id": PROJECT, "status": "completed", "sbom_refs": []})
    await db.scan_update_deltas.insert_one({"_id": scan_id, "project_id": PROJECT, "branch": BRANCH, "dep_count": 3})
    await db.scan_outdated_sets.insert_one({"_id": scan_id, "names": ["flask"], "n": 1})


async def _seed_chain(db: FakeDatabase, versions: dict[str, str]) -> None:
    """One scan per entry, each carrying a single package at the given version, with its delta."""
    await db.projects.insert_one({"_id": PROJECT, "name": PROJECT, "default_branch": BRANCH})
    for index, (scan_id, version) in enumerate(versions.items()):
        await db.scans.insert_one(
            {
                "_id": scan_id,
                "project_id": PROJECT,
                "branch": BRANCH,
                "created_at": T0 + timedelta(hours=index),
                "commit_hash": f"commit-{scan_id}",
                "status": "completed",
                "is_rescan": False,
                "sbom_refs": [],
            }
        )
        await db.dependencies.insert_one(
            {
                "_id": f"{scan_id}:flask",
                "scan_id": scan_id,
                "project_id": PROJECT,
                "name": "flask",
                "version": version,
                "type": "library",
                "purl": f"pkg:pypi/flask@{version}",
            }
        )
    for scan_id in versions:
        await record_scan_update_delta(db, scan_id)


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


@pytest.mark.asyncio
async def test_the_reconcile_recovers_the_movement_across_a_scan_retention_took():
    db = FakeDatabase()
    # The whole update happens at s2, so deleting it takes the movement out of the window
    # unless s3 is diffed against s1 again.
    await _seed_chain(db, {"s1": "1.0.0", "s2": "2.0.0", "s3": "2.0.0"})
    before = await db.scan_update_deltas.find_one({"_id": "s3"})
    assert (before or {})["prev_scan_id"] == "s2"
    assert (before or {})["total_updates"] == 0

    with patch("app.services.gridfs_maintenance.AsyncIOMotorGridFSBucket", return_value=AsyncMock()):
        await _delete_scans_and_related_data(db, ["s2"], "retention")
    exported = _severed_metric()

    report = await run_update_frequency_reconcile(db)

    assert report is not None
    assert report.drifted_chains == 1
    assert report.resolved == {"severed": 1}
    assert _severed_metric() == exported + 1
    after = await db.scan_update_deltas.find_one({"_id": "s3"})
    assert (after or {})["prev_scan_id"] == "s1"
    assert (after or {})["total_updates"] == 1


@pytest.mark.asyncio
async def test_a_predecessor_from_before_the_window_is_not_read_as_drift():
    db = FakeDatabase()
    await _seed_chain(db, {"s1": "1.0.0", "s2": "2.0.0"})
    await db.scan_update_deltas.update_one({"_id": "s2"}, {"$set": {"prev_created_at": T0 - timedelta(days=120)}})
    await db.scans.delete_one({"_id": "s1"})
    await db.scan_update_deltas.delete_one({"_id": "s1"})
    await db.scan_outdated_sets.delete_one({"_id": "s1"})

    report = await run_update_frequency_reconcile(db)

    assert report is not None
    assert report.drifted_chains == 0
