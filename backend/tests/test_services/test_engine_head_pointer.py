"""Finalizing a scan re-derives the project's head through the repository's head rule and caches it.

``latest_scan_id`` and ``project.stats`` are the head rule of ``app/repositories/scans.py`` cached,
so every case here asserts that the cache equals what the rule derives from the stored scans.
"""

from datetime import datetime, timedelta, timezone

import pytest

from app.core.constants import SCAN_STATUS_COMPLETED, SCAN_STATUS_FAILED, SCAN_STATUS_PENDING
from app.models.stats import Stats
from app.repositories.scans import ScanRepository
from app.services.analysis.engine import _finalize_scan_and_project
from app.services.rescan import build_rescan

_PROJECT_ID = "p1"
_MAIN = "main"
_FEATURE = "feature/spike"
_TAG = "v1.2.3"
_NOW = datetime(2026, 9, 1, tzinfo=timezone.utc)
_HOUR = timedelta(hours=1)
_SBOM_REFS = [{"type": "gridfs_reference", "gridfs_id": "g1"}]
_WORKER = "pod-a/worker-0"


async def _project(db, latest_scan_id=None, **fields):
    await db.projects.insert_one({"_id": _PROJECT_ID, "name": "proj", "latest_scan_id": latest_scan_id, **fields})


async def _scan(db, scan_id, created_at, branch=_MAIN, status=SCAN_STATUS_COMPLETED, **fields):
    await db.scans.insert_one(
        {
            "_id": scan_id,
            "project_id": _PROJECT_ID,
            "branch": branch,
            "status": status,
            "created_at": created_at,
            "stats": {"critical": 0},
            "sbom_refs": _SBOM_REFS,
            **fields,
        }
    )


async def _rescan(db, scan_id, root_id, created_at, status=SCAN_STATUS_COMPLETED):
    """The production shape: built from the lineage root, which points only at a delivered rescan."""
    rescan = build_rescan(await db.scans.find_one({"_id": root_id}))
    await db.scans.insert_one(
        rescan.model_dump(by_alias=True)
        | {"_id": scan_id, "created_at": created_at, "status": status, "stats": {"critical": 0}}
    )


async def _finalize(db, scan_id, status=SCAN_STATUS_COMPLETED, critical=0, sbom_generation=None, holder=_WORKER):
    scan_repo = ScanRepository(db)
    await db.scans.update_one({"_id": scan_id}, {"$set": {"status": "processing", "worker_id": holder}})
    return await _finalize_scan_and_project(
        scan_id,
        await scan_repo.get_by_id(scan_id),
        _PROJECT_ID,
        0,
        0,
        Stats(critical=critical),
        {"scan_id": scan_id, "status": status},
        scan_repo,
        status=status,
        sbom_generation=sbom_generation,
        worker_id=_WORKER,
        external_load_start=datetime.now(timezone.utc),
    )


async def _pointer(db):
    return (await db.projects.find_one({"_id": _PROJECT_ID}))["latest_scan_id"]


@pytest.mark.asyncio
async def test_a_rescan_of_the_head_build_takes_the_pointer_and_its_stats(db):
    await _project(db, "b1")
    await _scan(db, "b1", _NOW)
    await _rescan(db, "r1", "b1", _NOW + _HOUR)

    await _finalize(db, "r1", critical=7)

    project = await db.projects.find_one({"_id": _PROJECT_ID})
    assert project["latest_scan_id"] == "r1"
    assert project["stats"]["critical"] == 7


@pytest.mark.asyncio
async def test_a_rescan_leaves_the_projects_last_scanner_post_alone(db):
    await _project(db, "b1", last_scan_at=_NOW)
    await _scan(db, "b1", _NOW)
    await _rescan(db, "r1", "b1", _NOW + _HOUR)

    await _finalize(db, "r1")

    assert (await db.projects.find_one({"_id": _PROJECT_ID}))["last_scan_at"] == _NOW


@pytest.mark.asyncio
async def test_a_rescan_of_an_older_release_leaves_the_pointer_on_the_head(db):
    await _project(db, "b2")
    await _scan(db, "b1", _NOW - 30 * _HOUR)
    await _scan(db, "b2", _NOW)
    await _rescan(db, "r-release", "b1", _NOW + _HOUR)

    await _finalize(db, "r-release")

    assert await _pointer(db) == "b2"


@pytest.mark.asyncio
async def test_a_new_build_beats_a_pointer_to_a_rescan_created_after_it(db):
    """B2's pipeline opened before the rescan of B1 ran, so the rescan's date must not outrank B2."""
    await _project(db, "r1")
    await _scan(db, "b1", _NOW - _HOUR)
    await _scan(db, "b2", _NOW, status="processing")
    await _rescan(db, "r1", "b1", _NOW + _HOUR)
    await db.scans.update_one({"_id": "b1"}, {"$set": {"latest_rescan_id": "r1"}})

    await _finalize(db, "b2")

    assert await _pointer(db) == "b2"


@pytest.mark.asyncio
async def test_a_rescan_of_the_new_tip_takes_the_pointer_from_a_rescan_of_the_old_one(db):
    await _project(db, "r1")
    await _scan(db, "b1", _NOW - _HOUR)
    await _scan(db, "b2", _NOW)
    await _rescan(db, "r1", "b1", _NOW + _HOUR)
    await _rescan(db, "r2", "b2", _NOW + 2 * _HOUR)

    await _finalize(db, "r2")

    assert await _pointer(db) == "r2"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("default_branch", "scanned_branch", "expected"),
    [
        pytest.param(_MAIN, _FEATURE, "head", id="a_feature_branch_against_the_default"),
        pytest.param(_MAIN, _TAG, "head", id="a_tag_build_against_the_default"),
        pytest.param(_MAIN, _MAIN, "incoming", id="a_newer_scan_on_the_default"),
        pytest.param("trunk", _FEATURE, "incoming", id="a_default_branch_nothing_scans"),
    ],
)
async def test_the_pointer_stays_with_the_default_branch(db, default_branch, scanned_branch, expected):
    await _project(db, "head", default_branch=default_branch)
    await _scan(db, "head", _NOW)
    await _scan(
        db, "incoming", _NOW + _HOUR, branch=scanned_branch, commit_tag=_TAG if scanned_branch == _TAG else None
    )

    await _finalize(db, "incoming")

    assert await _pointer(db) == expected


@pytest.mark.asyncio
async def test_without_a_default_branch_a_tag_build_does_not_displace_a_branch_build(db):
    await _project(db, "head")
    await _scan(db, "head", _NOW)
    await _scan(db, "tag-build", _NOW + _HOUR, branch=_TAG, commit_tag=_TAG)

    await _finalize(db, "tag-build")

    assert await _pointer(db) == "head"


@pytest.mark.asyncio
async def test_without_a_default_branch_the_newest_branch_build_takes_the_pointer(db):
    await _project(db, "head")
    await _scan(db, "head", _NOW)
    await _scan(db, "feature-build", _NOW + _HOUR, branch=_FEATURE)

    await _finalize(db, "feature-build")

    assert await _pointer(db) == "feature-build"


@pytest.mark.asyncio
async def test_a_late_older_build_leaves_the_pointer_on_the_newer_one(db):
    await _project(db, "b2")
    await _scan(db, "b1", _NOW - _HOUR)
    await _scan(db, "b2", _NOW)

    await _finalize(db, "b1")

    assert await _pointer(db) == "b2"


@pytest.mark.asyncio
async def test_a_scan_without_an_sbom_does_not_replace_an_existing_pointer(db):
    await _project(db, "b1")
    await _scan(db, "b1", _NOW)
    await _scan(db, "sast-only", _NOW + _HOUR, sbom_refs=[])

    await _finalize(db, "sast-only")

    assert await _pointer(db) == "b1"


@pytest.mark.asyncio
@pytest.mark.parametrize("default_branch", [None, _MAIN])
async def test_a_rescan_of_the_sbom_build_heads_past_a_newer_scan_without_one(db, default_branch):
    await _project(db, "b1", default_branch=default_branch)
    await _scan(db, "b1", _NOW)
    await _scan(db, "sast-only", _NOW + _HOUR, sbom_refs=[])
    await _finalize(db, "sast-only")
    await _rescan(db, "r1", "b1", _NOW + 2 * _HOUR)

    await _finalize(db, "r1", critical=9)

    project = await db.projects.find_one({"_id": _PROJECT_ID})
    assert (project["latest_scan_id"], project["stats"]["critical"]) == ("r1", 9)
    assert (await ScanRepository(db).get_latest_active_scan(project)).id == "r1"


@pytest.mark.asyncio
async def test_a_feature_build_does_not_hand_head_to_a_newer_default_branch_scan_without_an_sbom(db):
    await _project(db, "b1", default_branch=_MAIN)
    await _scan(db, "b1", _NOW)
    await _scan(db, "sast-only", _NOW + _HOUR, sbom_refs=[])
    await _finalize(db, "sast-only")
    await _scan(db, "feature-build", _NOW + 2 * _HOUR, branch=_FEATURE)

    await _finalize(db, "feature-build")

    assert await _pointer(db) == "b1"


@pytest.mark.asyncio
async def test_a_scan_without_an_sbom_heads_a_project_that_has_nothing_else(db):
    await _project(db)
    await _scan(db, "sast-only", _NOW, sbom_refs=[])

    await _finalize(db, "sast-only")

    assert await _pointer(db) == "sast-only"


@pytest.mark.asyncio
async def test_in_a_project_without_sboms_the_newest_scan_takes_the_pointer(db):
    await _project(db, "sast-1", default_branch=_MAIN)
    await _scan(db, "sast-1", _NOW, sbom_refs=[])
    await _scan(db, "sast-2", _NOW + _HOUR, sbom_refs=[])

    await _finalize(db, "sast-2", critical=2)

    project = await db.projects.find_one({"_id": _PROJECT_ID})
    assert (project["latest_scan_id"], project["stats"]["critical"]) == ("sast-2", 2)


@pytest.mark.asyncio
async def test_a_failed_rescan_moves_neither_the_lineage_nor_the_pointer(db):
    """A failed rescan in front of a delivered one would otherwise hide it from every lineage walk."""
    await _project(db, "r1")
    await _scan(db, "b1", _NOW, latest_rescan_id="r1")
    await _rescan(db, "r1", "b1", _NOW + _HOUR)
    await _rescan(db, "r2", "b1", _NOW + 2 * _HOUR)

    await _finalize(db, "r2", status=SCAN_STATUS_FAILED)

    root = await db.scans.find_one({"_id": "b1"})
    assert root["latest_rescan_id"] == "r1"
    assert root["latest_run"] == {"scan_id": "r2", "status": SCAN_STATUS_FAILED}
    assert await _pointer(db) == "r1"
    assert (await ScanRepository(db).freshest_in_lineage(["b1"]))["b1"].scan_id == "r1"


@pytest.mark.asyncio
async def test_a_delivered_rescan_moves_the_lineage_onto_it(db):
    await _project(db, "b1")
    await _scan(db, "b1", _NOW)
    await _rescan(db, "r1", "b1", _NOW + _HOUR)

    await _finalize(db, "r1")

    assert (await db.scans.find_one({"_id": "b1"}))["latest_rescan_id"] == "r1"


@pytest.mark.asyncio
async def test_a_build_reanalysed_on_a_new_sbom_takes_head_back_from_its_rescan_of_the_old_one(db):
    await _project(db, "r1")
    await _scan(db, "b1", _NOW, sbom_generation=1)
    await _rescan(db, "r1", "b1", _NOW + _HOUR)
    await db.scans.update_one({"_id": "b1"}, {"$set": {"latest_rescan_id": "r1"}, "$inc": {"sbom_generation": 1}})

    await _finalize(db, "b1", critical=4, sbom_generation=2)

    project = await db.projects.find_one({"_id": _PROJECT_ID})
    assert (project["latest_scan_id"], project["stats"]["critical"]) == ("b1", 4)
    assert (await ScanRepository(db).freshest_in_lineage(["b1"]))["b1"].scan_id == "b1"


@pytest.mark.asyncio
async def test_a_rescan_of_a_replaced_sbom_does_not_reattach_to_its_build(db):
    await _project(db, "b1")
    await _scan(db, "b1", _NOW, sbom_generation=1)
    await _rescan(db, "r1", "b1", _NOW + _HOUR, status="processing")
    await db.scans.update_one({"_id": "b1"}, {"$inc": {"sbom_generation": 1}})

    await _finalize(db, "r1", sbom_generation=1)

    assert "latest_rescan_id" not in await db.scans.find_one({"_id": "b1"})
    assert await _pointer(db) == "b1"


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [SCAN_STATUS_COMPLETED, SCAN_STATUS_FAILED])
async def test_a_run_whose_sbom_was_replaced_meanwhile_is_rescheduled_not_finalized(db, status):
    await _project(db, "b0")
    await _scan(db, "b0", _NOW - _HOUR)
    await _scan(db, "b1", _NOW, sbom_generation=2)

    assert await _finalize(db, "b1", status=status, sbom_generation=1) == SCAN_STATUS_PENDING

    assert (await db.scans.find_one({"_id": "b1"}))["status"] == "pending"
    assert await _pointer(db) == "b0"


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [SCAN_STATUS_COMPLETED, SCAN_STATUS_FAILED])
async def test_a_run_a_scanner_result_overtook_is_rescheduled_not_finalized(db, status):
    await _project(db, "b0")
    await _scan(db, "b0", _NOW - _HOUR)
    await _scan(db, "b1", _NOW, last_result_at=datetime.now(timezone.utc) + timedelta(minutes=1))

    assert await _finalize(db, "b1", status=status) == SCAN_STATUS_PENDING

    assert (await db.scans.find_one({"_id": "b1"}))["status"] == "pending"
    assert await _pointer(db) == "b0"


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [SCAN_STATUS_COMPLETED, SCAN_STATUS_FAILED])
async def test_a_run_whose_claim_moved_to_another_worker_leaves_the_scan_to_it(db, status):
    await _project(db, "b0")
    await _scan(db, "b0", _NOW - _HOUR)
    await _scan(db, "b1", _NOW)

    assert await _finalize(db, "b1", status=status, holder="pod-b/worker-0") is None

    stored = await db.scans.find_one({"_id": "b1"})
    assert (stored["status"], stored["worker_id"]) == ("processing", "pod-b/worker-0")
    assert await _pointer(db) == "b0"
