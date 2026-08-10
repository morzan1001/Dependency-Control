"""Branch/scan resolution for inventory and export views."""

from datetime import datetime, timedelta, timezone

import pytest

from app.models.project import Project
from app.services.inventory.scan_resolution import (
    active_branches,
    latest_completed_scans_by_branch,
    resolve_inventory_scan,
)

_NOW = datetime(2026, 8, 10, 12, 0, tzinfo=timezone.utc)


def _scan(scan_id: str, branch: str, *, status: str = "completed", age_hours: int = 0) -> dict:
    return {
        "_id": scan_id,
        "project_id": "p1",
        "branch": branch,
        "status": status,
        "created_at": _NOW - timedelta(hours=age_hours),
        "commit_hash": f"c-{scan_id}",
    }


def _project(**kwargs) -> Project:
    return Project(id="p1", name="proj", **kwargs)


@pytest.mark.asyncio
async def test_active_branches_excludes_deleted(db):
    for doc in (_scan("s1", "main"), _scan("s2", "old"), _scan("s3", "dev")):
        await db.scans.insert_one(doc)
    project = _project(deleted_branches=["old"])
    assert await active_branches(db, project) == ["dev", "main"]


@pytest.mark.asyncio
async def test_latest_completed_per_branch_skips_branches_without_completed_scan(db):
    await db.scans.insert_one(_scan("s1", "main", age_hours=2))
    await db.scans.insert_one(_scan("s2", "main", age_hours=1))
    await db.scans.insert_one(_scan("s3", "dev", status="processing"))
    scans = await latest_completed_scans_by_branch(db, _project())
    assert [(s.id, s.branch) for s in scans] == [("s2", "main")]


@pytest.mark.asyncio
async def test_resolve_prefers_explicit_branch_then_default(db):
    await db.scans.insert_one(_scan("s1", "main"))
    await db.scans.insert_one(_scan("s2", "dev"))
    project = _project(default_branch="main")
    assert (await resolve_inventory_scan(db, project, "dev")).id == "s2"
    assert (await resolve_inventory_scan(db, project, None)).id == "s1"


@pytest.mark.asyncio
async def test_resolve_falls_back_to_latest_active_scan_without_default(db):
    await db.scans.insert_one(_scan("s1", "feature-x"))
    assert (await resolve_inventory_scan(db, _project(), None)).id == "s1"


@pytest.mark.asyncio
async def test_resolve_returns_none_for_deleted_or_unknown_branch(db):
    await db.scans.insert_one(_scan("s1", "old"))
    project = _project(deleted_branches=["old"])
    assert await resolve_inventory_scan(db, project, "old") is None
    assert await resolve_inventory_scan(db, project, "nope") is None
