"""The overview reads branch tips from the whole project, so a page of scans cannot hide a branch."""

from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio

_NOW = datetime(2026, 9, 1, tzinfo=timezone.utc)
_AN_HOUR = timedelta(hours=1)
_PROJECT = "test-project-id"
_BUSY_BRANCH = "main"
_QUIET_BRANCH = "release/2.0"
_DELETED_BRANCH = "release/1.0"
_QUIET_TIP = "quiet-tip"
_STATUS = "completed"
# More scans than the scan-list endpoint will return on any one page.
_BUSY_BRANCH_SCANS = 120


async def _seed(db) -> None:
    await db.projects.update_one({"_id": _PROJECT}, {"$set": {"deleted_branches": [_DELETED_BRANCH]}}, upsert=True)
    for index in range(_BUSY_BRANCH_SCANS):
        await db.scans.insert_one(
            {
                "_id": f"busy-{index:04d}",
                "project_id": _PROJECT,
                "branch": _BUSY_BRANCH,
                "status": _STATUS,
                "is_rescan": False,
                "created_at": _NOW - index * _AN_HOUR,
            }
        )
    await db.scans.insert_one(
        {
            "_id": _QUIET_TIP,
            "project_id": _PROJECT,
            "branch": _QUIET_BRANCH,
            "status": _STATUS,
            "is_rescan": False,
            "created_at": _NOW - (_BUSY_BRANCH_SCANS + 10) * _AN_HOUR,
        }
    )
    await db.scans.insert_one(
        {
            "_id": "on-deleted-branch",
            "project_id": _PROJECT,
            "branch": _DELETED_BRANCH,
            "status": _STATUS,
            "is_rescan": False,
            "created_at": _NOW,
        }
    )


@pytest_asyncio.fixture
async def seeded(client, db):
    await _seed(db)
    return client


@pytest.mark.asyncio
async def test_lists_a_branch_the_scan_list_page_cannot_reach(seeded, member_auth_headers):
    response = await seeded.get(f"/api/v1/projects/{_PROJECT}/scans/branch-tips", headers=member_auth_headers)

    assert response.status_code == 200
    assert [row["branch"] for row in response.json()["branches"]] == [_BUSY_BRANCH, _QUIET_BRANCH]


@pytest.mark.asyncio
async def test_counts_the_whole_branch_rather_than_a_page_of_it(seeded, member_auth_headers):
    response = await seeded.get(f"/api/v1/projects/{_PROJECT}/scans/branch-tips", headers=member_auth_headers)

    counts = {row["branch"]: row["scan_count"] for row in response.json()["branches"]}
    assert counts == {_BUSY_BRANCH: _BUSY_BRANCH_SCANS, _QUIET_BRANCH: 1}


@pytest.mark.asyncio
async def test_answers_branches_only(seeded, member_auth_headers):
    """Release rows are the one authority on what a release is, so the tips carry no flag-based guess."""
    response = await seeded.get(f"/api/v1/projects/{_PROJECT}/scans/branch-tips", headers=member_auth_headers)

    assert set(response.json()) == {"branches"}
