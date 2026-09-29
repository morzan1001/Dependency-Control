"""The head writer's derivation and pointer guard, on a real server."""

from datetime import datetime, timedelta, timezone

import pytest

from app.repositories.scans import ScanRepository

_NOW = datetime(2026, 9, 1, tzinfo=timezone.utc)
_SBOM_REFS = [{"type": "gridfs_reference", "gridfs_id": "g1"}]


async def _scan(db, scan_id: str, branch: str, hours_old: int, **fields) -> None:
    await db.scans.insert_one(
        {
            "_id": scan_id,
            "project_id": "p1",
            "branch": branch,
            "status": "completed",
            "created_at": _NOW - timedelta(hours=hours_old),
            "sbom_refs": _SBOM_REFS,
            "stats": {"critical": hours_old},
            **fields,
        }
    )


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_a_project_that_never_cached_a_head_gets_the_default_branch_tip(db):
    await _scan(db, "main-tip", "main", 5)
    await _scan(db, "feature", "feature/x", 1)
    await _scan(db, "tag-build", "v1.0", 0, commit_tag="v1.0")
    await db.projects.insert_one({"_id": "p1", "name": "p", "default_branch": "main"})

    assert await ScanRepository(db).sync_project_head("p1") == "main-tip"

    project = await db.projects.find_one({"_id": "p1"})
    assert (project["latest_scan_id"], project["stats"]) == ("main-tip", {"critical": 5})


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_without_a_default_branch_a_branch_build_outranks_a_newer_tag_build(db):
    await _scan(db, "feature", "feature/x", 3)
    await _scan(db, "tag-build", "v1.0", 0, commit_tag="v1.0")
    await db.projects.insert_one({"_id": "p1", "name": "p", "latest_scan_id": "tag-build"})

    assert await ScanRepository(db).sync_project_head("p1") == "feature"
    assert (await db.projects.find_one({"_id": "p1"}))["latest_scan_id"] == "feature"
