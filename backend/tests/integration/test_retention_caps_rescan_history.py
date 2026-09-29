"""Every scheduled rescan stores a full copy of findings, dependencies and raw results, so age
retention alone keeps retention_days * 24 / interval of them per build."""

from datetime import datetime, timedelta, timezone

import pytest

from app.core.constants import RESCAN_HISTORY_RUNS
from app.core.housekeeping import _run_retention

_NOW = datetime.now(timezone.utc)
_ROOT = "build"


def _build(project_id: str = "p1", **fields) -> dict:
    return {
        "_id": _ROOT if project_id == "p1" else f"{project_id}-build",
        "project_id": project_id,
        "branch": "main",
        "status": "completed",
        "is_rescan": False,
        "original_scan_id": None,
        "created_at": _NOW - timedelta(days=30),
        **fields,
    }


def _rescan(run: int, status: str = "completed", root: str = _ROOT, project_id: str = "p1", **fields) -> dict:
    """Run 0 is the newest; each run is a day older than the one before."""
    return {
        "_id": f"{root}-run-{run}",
        "project_id": project_id,
        "branch": "main",
        "status": status,
        "is_rescan": True,
        "original_scan_id": root,
        "created_at": _NOW - timedelta(days=run),
        **fields,
    }


def _project(project_id: str = "p1", retention_action: str = "delete") -> dict:
    return {"_id": project_id, "name": project_id, "retention_days": 90, "retention_action": retention_action}


async def _remaining(db) -> set[str]:
    return {doc["_id"] async for doc in db.scans.find({}, {"_id": 1})}


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_a_build_keeps_its_newest_usable_rescans_and_loses_the_older_ones(db):
    runs = [_rescan(run) for run in range(RESCAN_HISTORY_RUNS + 3)]
    await db.projects.insert_one(_project())
    await db.scans.insert_many([_build(latest_rescan_id=runs[0]["_id"]), *runs])

    await _run_retention(db)

    assert await _remaining(db) == {_ROOT, *(run["_id"] for run in runs[:RESCAN_HISTORY_RUNS])}


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_failed_runs_do_not_count_towards_the_kept_history(db):
    """A failed run carries no usable analysis, so counting it would leave fewer readable runs."""
    newest_failed = _rescan(0, "failed")
    usable = [_rescan(run) for run in range(1, RESCAN_HISTORY_RUNS + 1)]
    older = [_rescan(RESCAN_HISTORY_RUNS + 1, "failed"), _rescan(RESCAN_HISTORY_RUNS + 2)]
    await db.projects.insert_one(_project())
    await db.scans.insert_many([_build(latest_rescan_id=usable[0]["_id"]), newest_failed, *usable, *older])

    await _run_retention(db)

    assert await _remaining(db) == {_ROOT, newest_failed["_id"], *(run["_id"] for run in usable)}


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_the_current_analysis_pinned_and_active_runs_outlive_the_cap(db):
    runs = [_rescan(run) for run in range(RESCAN_HISTORY_RUNS)]
    current = _rescan(RESCAN_HISTORY_RUNS)
    pinned = _rescan(RESCAN_HISTORY_RUNS + 1, pinned=True)
    pending = _rescan(RESCAN_HISTORY_RUNS + 2, "pending")
    dropped = _rescan(RESCAN_HISTORY_RUNS + 3)
    await db.projects.insert_one(_project())
    await db.scans.insert_many([_build(latest_rescan_id=current["_id"]), *runs, current, pinned, pending, dropped])

    await _run_retention(db)

    assert await _remaining(db) == {
        _ROOT,
        *(run["_id"] for run in runs),
        current["_id"],
        pinned["_id"],
        pending["_id"],
    }


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_a_project_that_keeps_its_scans_forever_keeps_every_rescan(db):
    kept_root = "keep-build"
    capped = [_rescan(run) for run in range(RESCAN_HISTORY_RUNS + 1)]
    kept = [_rescan(run, root=kept_root, project_id="keep") for run in range(RESCAN_HISTORY_RUNS + 1)]
    await db.projects.insert_many([_project(), _project("keep", retention_action="none")])
    await db.scans.insert_many([_build(), *capped, _build("keep"), *kept])

    await _run_retention(db)

    remaining = await _remaining(db)
    assert {run["_id"] for run in kept} <= remaining
    assert capped[-1]["_id"] not in remaining
