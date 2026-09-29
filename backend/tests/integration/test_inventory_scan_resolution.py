"""Which scan the inventory and findings-export views read: the head rule, per branch or for the project."""

from datetime import datetime, timedelta, timezone

import pytest
from fastapi import HTTPException

from app.api.v1.endpoints.inventory import _resolve_scan_or_404
from app.models.project import Project
from app.repositories.scans import ScanRepository

_NOW = datetime(2026, 8, 10, 12, 0, tzinfo=timezone.utc)


def _scan(scan_id: str, branch: str, *, status: str = "completed", age_hours: int = 0, **fields) -> dict:
    return {
        "_id": scan_id,
        "project_id": "p1",
        "branch": branch,
        "status": status,
        "created_at": _NOW - timedelta(hours=age_hours),
        "commit_hash": f"c-{scan_id}",
        **fields,
    }


def _project(**kwargs) -> Project:
    return Project(id="p1", name="proj", **kwargs)


async def _seed(db, *scans: dict) -> None:
    for doc in scans:
        await db.scans.insert_one(doc)


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_branch_tips_leave_out_deleted_branches_and_tag_builds(db):
    await _seed(
        db,
        _scan("s1", "main"),
        _scan("s2", "old"),
        _scan("s3", "dev"),
        _scan("s4", "v1.0", commit_tag="v1.0"),
    )

    tips = await ScanRepository(db).branch_tips("p1", ["old"])

    assert [(branch, tip["_id"]) for branch, _count, tip in tips] == [("dev", "s3"), ("main", "s1")]


@pytest.mark.asyncio
async def test_a_branch_without_a_usable_scan_has_no_tip(db):
    await _seed(
        db, _scan("s1", "main", age_hours=2), _scan("s2", "main", age_hours=1), _scan("s3", "dev", status="processing")
    )

    tips = await ScanRepository(db).branch_tips("p1")

    assert [(branch, count, tip and tip["_id"]) for branch, count, tip in tips] == [("dev", 1, None), ("main", 2, "s2")]


@pytest.mark.asyncio
async def test_a_branch_tip_is_the_newest_build_not_a_rescan_of_an_older_one(db):
    """A rescan carries today's date over an older commit, so it must not stand for the branch."""
    await _seed(
        db,
        _scan("old-build", "main", age_hours=48),
        _scan("new-build", "main", age_hours=24),
        _scan("old-rescan", "main", age_hours=1, is_rescan=True, original_scan_id="old-build"),
    )

    assert (await ScanRepository(db).branch_tip("p1", "main")).id == "new-build"


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_a_branch_tip_is_the_newest_build_that_carries_an_sbom(db):
    await _seed(
        db,
        _scan("sbom-build", "main", age_hours=24, sbom_refs=[{"gridfs_id": "g1"}]),
        _scan("sast-only", "main", age_hours=1, sbom_refs=[]),
        _scan("legacy", "main", age_hours=0),
    )

    assert (await ScanRepository(db).branch_tip("p1", "main")).id == "sbom-build"


@pytest.mark.asyncio
async def test_a_branch_tip_reports_the_delivered_rescan_of_its_newest_build(db):
    await _seed(
        db,
        _scan("build", "main", age_hours=24, latest_rescan_id="rescan"),
        _scan("rescan", "main", age_hours=1, is_rescan=True, original_scan_id="build"),
    )

    assert (await ScanRepository(db).branch_tip("p1", "main")).id == "rescan"


@pytest.mark.asyncio
async def test_resolve_prefers_explicit_branch_then_default(db):
    await _seed(db, _scan("s1", "main"), _scan("s2", "dev"))
    project = _project(default_branch="main")
    assert (await _resolve_scan_or_404(db, project, "dev")).id == "s2"
    assert (await _resolve_scan_or_404(db, project, None)).id == "s1"


@pytest.mark.asyncio
async def test_resolve_falls_back_to_head_without_default(db):
    await _seed(db, _scan("s1", "feature-x"))
    assert (await _resolve_scan_or_404(db, _project(), None)).id == "s1"


@pytest.mark.asyncio
@pytest.mark.parametrize("branch", ["old", "nope"])
async def test_resolve_answers_404_for_a_deleted_or_unknown_branch(db, branch):
    await _seed(db, _scan("s1", "old"))
    with pytest.raises(HTTPException) as caught:
        await _resolve_scan_or_404(db, _project(deleted_branches=["old"]), branch)
    assert caught.value.status_code == 404


@pytest.mark.asyncio
async def test_resolve_skips_deleted_default_branch(db):
    await _seed(db, _scan("s1", "old", age_hours=1), _scan("s2", "main", age_hours=2))
    project = _project(default_branch="old", deleted_branches=["old"])
    assert (await _resolve_scan_or_404(db, project, None)).id == "s2"
