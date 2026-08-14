"""W8 part 1: the branch sync backfills projects.default_branch from the VCS.

All 530 production projects without a default_branch have a VCS link (436 GitLab,
94 GitHub), so the project views need not fall back to "most recently scanned branch".
"""

from unittest.mock import AsyncMock, patch

import pytest

from app.core.housekeeping import sync_project_branches
from tests.mocks.fake_mongo import FakeDatabase

MODULE = "app.core.housekeeping"


async def _run(project_doc: dict, db: FakeDatabase) -> dict:
    await db.projects.insert_one(project_doc)
    await db.scans.insert_one({"_id": "s1", "project_id": project_doc["_id"], "branch": "main"})
    with (
        patch(f"{MODULE}._fetch_vcs_branches", AsyncMock(return_value=["main", "develop"])),
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
async def test_an_existing_default_branch_is_never_overwritten():
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
