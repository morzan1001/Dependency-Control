"""/branches names exactly one default branch, also for projects that never got a ``default_branch``
(selecting every branch multiplies the counters), and that default is the branch head resolves to."""

from datetime import datetime, timedelta, timezone

import pytest

_NOW = datetime(2026, 8, 14, 12, 0, tzinfo=timezone.utc)
_PROJECT_ID = "test-project-id"


async def _seed_branch(
    db, branch: str, *, age_hours: int, status: str = "completed", suffix: str = "", **fields
) -> None:
    await db.scans.insert_one(
        {
            "_id": f"scan-{branch}{suffix}",
            "project_id": _PROJECT_ID,
            "branch": branch,
            "status": status,
            "created_at": _NOW - timedelta(hours=age_hours),
            **fields,
        }
    )


async def _get_branches(client, headers) -> list[dict]:
    response = await client.get(f"/api/v1/projects/{_PROJECT_ID}/branches", headers=headers)
    assert response.status_code == 200, response.text
    return response.json()


@pytest.mark.asyncio
async def test_project_without_default_branch_still_names_one_default(client, db, member_auth_headers):
    """525+ prod projects have no default_branch; the newest scanned branch must win."""
    await _seed_branch(db, "main", age_hours=50)
    await _seed_branch(db, "feature-a", age_hours=3)
    await _seed_branch(db, "feature-b", age_hours=90)

    branches = await _get_branches(client, member_auth_headers)

    defaults = [b["name"] for b in branches if b["is_default"]]
    assert defaults == ["feature-a"]
    assert len(branches) == 3


@pytest.mark.asyncio
async def test_configured_default_branch_wins_over_recency(client, db, member_auth_headers):
    await _seed_branch(db, "main", age_hours=50)
    await _seed_branch(db, "feature-a", age_hours=3)
    await db.projects.update_one({"_id": _PROJECT_ID}, {"$set": {"default_branch": "main"}})

    branches = await _get_branches(client, member_auth_headers)

    assert [b["name"] for b in branches if b["is_default"]] == ["main"]


@pytest.mark.asyncio
async def test_deleted_default_branch_falls_back_to_an_active_one(client, db, member_auth_headers):
    await _seed_branch(db, "main", age_hours=50)
    await _seed_branch(db, "feature-a", age_hours=3)
    await db.projects.update_one(
        {"_id": _PROJECT_ID},
        {"$set": {"default_branch": "main", "deleted_branches": ["main"]}},
    )

    branches = await _get_branches(client, member_auth_headers)

    assert [b["name"] for b in branches if b["is_default"]] == ["feature-a"]


@pytest.mark.asyncio
async def test_a_branch_whose_scans_all_failed_never_becomes_the_default(client, db, member_auth_headers):
    """Ranking on raw activity would open the project on a branch that renders nothing."""
    await _seed_branch(db, "main", age_hours=50)
    await _seed_branch(db, "broken", age_hours=1, status="failed")
    await _seed_branch(db, "broken", age_hours=2, status="processing", suffix="-b")

    branches = await _get_branches(client, member_auth_headers)

    assert [b["name"] for b in branches if b["is_default"]] == ["main"]
    # last_scan_at keeps meaning "last activity", so the failed run is still visible.
    assert next(b for b in branches if b["name"] == "broken")["last_scan_at"] is not None


@pytest.mark.asyncio
async def test_without_a_usable_scan_the_first_branch_by_name_is_the_default(client, db, member_auth_headers):
    await _seed_branch(db, "zeta", age_hours=1, status="failed")
    await _seed_branch(db, "alpha", age_hours=2, status="failed")

    branches = await _get_branches(client, member_auth_headers)

    assert [b["name"] for b in branches if b["is_default"]] == ["alpha"]


@pytest.mark.asyncio
async def test_a_rescan_of_an_old_release_branch_does_not_make_it_the_default(client, db, member_auth_headers):
    """A rescan carries today's date over an old commit, so it is no sign of what CI builds."""
    await _seed_branch(db, "main", age_hours=50)
    await _seed_branch(db, "release/1.2", age_hours=90)
    await _seed_branch(
        db, "release/1.2", age_hours=1, suffix="-rescan", is_rescan=True, original_scan_id="scan-release/1.2"
    )

    branches = await _get_branches(client, member_auth_headers)

    assert [b["name"] for b in branches if b["is_default"]] == ["main"]


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_a_tag_pipeline_names_no_branch(client, db, member_auth_headers):
    await _seed_branch(db, "main", age_hours=50)
    await _seed_branch(db, "v2.0.0", age_hours=1, commit_tag="v2.0.0")

    branches = await _get_branches(client, member_auth_headers)

    assert [(b["name"], b["is_default"]) for b in branches] == [("main", True)]


@pytest.mark.asyncio
async def test_the_default_is_the_branch_head_reports_when_the_configured_one_holds_nothing_usable(
    client, db, member_auth_headers
):
    await _seed_branch(db, "main", age_hours=1, status="failed")
    await _seed_branch(db, "develop", age_hours=5)
    await db.projects.update_one({"_id": _PROJECT_ID}, {"$set": {"default_branch": "main"}})

    branches = await _get_branches(client, member_auth_headers)

    assert [b["name"] for b in branches if b["is_default"]] == ["develop"]
