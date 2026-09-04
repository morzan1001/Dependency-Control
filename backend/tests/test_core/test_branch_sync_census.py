"""The branch census counts branches, not the tag names tag pipelines recorded as branches."""

from typing import Any
from unittest.mock import AsyncMock, patch

import pytest

from app.core.housekeeping import sync_project_branches
from tests.mocks.fake_mongo import FakeDatabase

_MODULE = "app.core.housekeeping"

_PROJECT_ID = "p1"
_PROJECT_NAME = "proj"
_MAIN_BRANCH = "main"
_GONE_BRANCH = "feature-x"
_TAG = "v1.2.3"

_TAG_BUILD_ID = "tag-build"
_BRANCH_BUILD_ID = "branch-build"
_GONE_BRANCH_BUILD_ID = "gone-build"

_VCS_BRANCHES = [_MAIN_BRANCH]


def _project() -> dict[str, Any]:
    return {"_id": _PROJECT_ID, "name": _PROJECT_NAME, "default_branch": _MAIN_BRANCH}


async def _sync(db: FakeDatabase) -> dict[str, Any]:
    project = _project()
    await db.projects.insert_one(project)
    with patch(f"{_MODULE}._fetch_vcs_branches", AsyncMock(return_value=_VCS_BRANCHES)):
        await sync_project_branches(project, db)
    stored: dict[str, Any] = await db.projects.find_one({"_id": _PROJECT_ID})
    return stored


@pytest.mark.asyncio
async def test_a_tag_build_does_not_file_its_tag_as_a_deleted_branch() -> None:
    db = FakeDatabase()
    await db.scans.insert_one({"_id": _TAG_BUILD_ID, "project_id": _PROJECT_ID, "branch": _TAG, "commit_tag": _TAG})
    await db.scans.insert_one(
        {"_id": _BRANCH_BUILD_ID, "project_id": _PROJECT_ID, "branch": _MAIN_BRANCH, "commit_tag": None}
    )

    assert (await _sync(db))["deleted_branches"] == []


@pytest.mark.asyncio
async def test_a_branch_the_vcs_no_longer_has_is_still_reported_as_deleted() -> None:
    db = FakeDatabase()
    await db.scans.insert_one(
        {"_id": _GONE_BRANCH_BUILD_ID, "project_id": _PROJECT_ID, "branch": _GONE_BRANCH, "commit_tag": None}
    )

    assert (await _sync(db))["deleted_branches"] == [_GONE_BRANCH]


@pytest.mark.asyncio
async def test_a_tagged_build_of_a_real_branch_still_counts_that_branch() -> None:
    """The new scanner reports the default branch on a tag pipeline, so branch and tag differ."""
    db = FakeDatabase()
    await db.scans.insert_one(
        {"_id": _TAG_BUILD_ID, "project_id": _PROJECT_ID, "branch": _GONE_BRANCH, "commit_tag": _TAG}
    )

    assert (await _sync(db))["deleted_branches"] == [_GONE_BRANCH]
