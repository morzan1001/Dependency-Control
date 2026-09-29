"""The branch sync takes projects.default_branch from the VCS while the stored one is missing or
names a branch the VCS deleted, and moves the cached head along with it."""

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch

import pytest

from app.core.housekeeping import sync_project_branches
from tests.mocks.fake_mongo import FakeDatabase

MODULE = "app.core.housekeeping"
_T0 = datetime(2026, 9, 1, tzinfo=timezone.utc)
_DEVELOP_CRITICALS = 3


async def _run(project_doc: dict, db: FakeDatabase, vcs_branches: tuple[str, ...] = ("main", "develop")) -> dict:
    await db.projects.insert_one(project_doc)
    await db.scans.insert_one(
        {"_id": "s1", "project_id": project_doc["_id"], "branch": "main", "status": "completed", "created_at": _T0}
    )
    await db.scans.insert_one(
        {
            "_id": "s-develop",
            "project_id": project_doc["_id"],
            "branch": "develop",
            "status": "completed",
            "created_at": _T0 - timedelta(days=1),
            "stats": {"critical": _DEVELOP_CRITICALS},
        }
    )
    with (
        patch(f"{MODULE}._fetch_vcs_branches", AsyncMock(return_value=list(vcs_branches))),
        patch(f"{MODULE}._fetch_vcs_default_branch", AsyncMock(return_value="develop")) as fetch_default,
    ):
        await sync_project_branches(project_doc, db)
    stored = await db.projects.find_one({"_id": project_doc["_id"]})
    stored["_fetch_default_called"] = fetch_default.await_count
    return stored


@pytest.mark.asyncio
async def test_missing_default_branch_is_backfilled_from_the_vcs():
    db = FakeDatabase()
    stored = await _run({"_id": "p1", "name": "p", "gitlab_instance_id": "gl", "gitlab_project_id": "42"}, db)
    assert stored["default_branch"] == "develop"


@pytest.mark.asyncio
async def test_a_backfilled_default_branch_takes_the_cached_head_along():
    db = FakeDatabase()
    stored = await _run(
        {"_id": "p1", "name": "p", "latest_scan_id": "s1", "gitlab_instance_id": "gl", "gitlab_project_id": "42"}, db
    )
    assert stored["latest_scan_id"] == "s-develop"
    assert stored["stats"]["critical"] == _DEVELOP_CRITICALS


@pytest.mark.asyncio
async def test_a_default_branch_the_vcs_deleted_is_replaced_by_the_vcs_default():
    """A renamed default branch (master to develop) would otherwise leave head roaming over whichever
    branch built last."""
    db = FakeDatabase()
    stored = await _run(
        {
            "_id": "p3",
            "name": "p",
            "default_branch": "main",
            "latest_scan_id": "s1",
            "gitlab_instance_id": "gl",
            "gitlab_project_id": "42",
        },
        db,
        vcs_branches=("develop",),
    )
    assert stored["default_branch"] == "develop"
    assert stored["deleted_branches"] == ["main"]
    assert stored["latest_scan_id"] == "s-develop"


@pytest.mark.asyncio
async def test_an_existing_live_default_branch_is_kept():
    db = FakeDatabase()
    stored = await _run(
        {
            "_id": "p2",
            "name": "p",
            "default_branch": "main",
            "gitlab_instance_id": "gl",
            "gitlab_project_id": "42",
        },
        db,
    )
    assert stored["default_branch"] == "main"
    # A project that already knows its default branch must not cost an extra VCS call.
    assert stored["_fetch_default_called"] == 0
