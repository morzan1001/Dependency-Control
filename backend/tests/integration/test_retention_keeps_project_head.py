"""Retention expires scans by age, yet a project's head has to survive it however old it is."""

from datetime import datetime, timedelta, timezone

import pytest

from app.core.housekeeping import _run_retention
from app.repositories.scans import ScanRepository

_NOW = datetime.now(timezone.utc)
_RETENTION_DAYS = 90


def _scan(scan_id: str, branch: str, age_days: int, project_id: str = "p1") -> dict:
    return {
        "_id": scan_id,
        "project_id": project_id,
        "branch": branch,
        "status": "completed",
        "created_at": _NOW - timedelta(days=age_days),
        "sbom_refs": [{"storage": "inline"}],
    }


def _project(project_id: str, **fields) -> dict:
    return {
        "_id": project_id,
        "name": project_id,
        "retention_days": _RETENTION_DAYS,
        "retention_action": "delete",
        **fields,
    }


async def _remaining(db) -> set[str]:
    return {doc["_id"] async for doc in db.scans.find({}, {"_id": 1})}


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_an_old_default_branch_head_survives_and_a_newer_feature_build_does_not_take_over(db):
    await db.projects.insert_one(_project("p1", default_branch="main", latest_scan_id="main-head"))
    await db.scans.insert_many(
        [_scan("main-older", "main", 120), _scan("main-head", "main", 100), _scan("feature", "feature", 10)]
    )

    await _run_retention(db)

    assert await _remaining(db) == {"main-head", "feature"}
    project = await db.projects.find_one({"_id": "p1"})
    assert (await ScanRepository(db).get_latest_active_scan_ids([project])) == {"p1": "main-head"}


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_a_project_without_recent_builds_keeps_its_head(db):
    await db.projects.insert_one(_project("idle"))
    await db.scans.insert_many([_scan("idle-old", "main", 200, "idle"), _scan("idle-head", "main", 150, "idle")])

    await _run_retention(db)

    assert await _remaining(db) == {"idle-head"}
