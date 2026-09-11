"""What an ingest's team sync writes: its own owners, and nobody else's.

Every case applies the stages the writer produced to a seeded document and asserts on what is
stored afterwards, because the whole point of the phase is the end state of one atomic write —
a test that only inspected the returned stages would pass on a pipeline that stores the wrong thing.
"""

from unittest.mock import AsyncMock, MagicMock

import pytest

from app.api.deps import _github_team_sync_stages, _gitlab_team_sync_stages
from app.core.constants import MAX_PROJECT_TEAMS
from app.models.project import Project
from app.repositories.projects import ProjectRepository
from app.services.github import GitHubTeamSyncResult
from app.services.gitlab import GitLabTeamSyncResult
from tests.mocks.fake_mongo import FakeDatabase

_PROJECT_ID = "p-1"


async def _seed(db, **ownership) -> Project:
    doc = {
        "_id": _PROJECT_ID,
        "name": "grp/proj",
        "gitlab_instance_id": "inst-1",
        "gitlab_project_id": 100,
        "github_instance_id": "gh-1",
        "github_repository_id": "123456",
        **ownership,
    }
    await db.projects.insert_one(doc)
    return Project(**doc)


async def _apply(db, project: Project, stages: list[dict]) -> dict:
    if stages:
        await ProjectRepository(db).update_raw(str(project.id), stages)
    return await db.projects.find_one({"_id": str(project.id)})


async def _gitlab_sync(db, project: Project, resolved: list[str] | None) -> tuple[dict, list[dict]]:
    service = MagicMock()
    service.get_project_details = AsyncMock(return_value=MagicMock())
    service.sync_team_from_gitlab = AsyncMock(return_value=GitLabTeamSyncResult(resolved))
    stages = await _gitlab_team_sync_stages(project, 100, "grp/proj", service, db)
    return await _apply(db, project, stages), stages


async def _github_sync(db, project: Project, resolved: list[str] | None) -> tuple[dict, list[dict]]:
    service = MagicMock()
    service.sync_team_from_github = AsyncMock(return_value=GitHubTeamSyncResult(resolved))
    stages = await _github_team_sync_stages(project, "acme", "acme/widgets", service, db)
    return await _apply(db, project, stages), stages


@pytest.mark.asyncio
async def test_a_sync_does_not_evict_a_manual_co_owner():
    """The one that matters: a CI ingest runs on every pipeline, so a blind replace would delete
    an operator's assignment within minutes of them making it."""
    db = FakeDatabase()
    project = await _seed(
        db,
        team_ids=["gl-old", "by-hand"],
        team_sources={"gl-old": "gitlab", "by-hand": "manual"},
        team_id="gl-old",
        team_source="gitlab",
    )

    stored, _ = await _gitlab_sync(db, project, ["gl-new"])

    assert sorted(stored["team_ids"]) == ["by-hand", "gl-new"]
    assert stored["team_sources"] == {"by-hand": "manual", "gl-new": "gitlab"}


@pytest.mark.asyncio
async def test_a_project_that_moved_group_loses_the_owner_it_left():
    """The mirror image: a union would keep the old group forever, so every transfer would widen
    access instead of moving it."""
    db = FakeDatabase()
    project = await _seed(db, team_ids=["gl-old"], team_sources={"gl-old": "gitlab"}, team_id="gl-old")

    stored, _ = await _gitlab_sync(db, project, ["gl-new"])

    assert stored["team_ids"] == ["gl-new"]
    assert stored["team_sources"] == {"gl-new": "gitlab"}
    assert stored["team_id"] == "gl-new"
    assert stored["team_source"] == "gitlab"


@pytest.mark.asyncio
async def test_a_sync_that_could_not_be_asked_writes_nothing():
    db = FakeDatabase()
    project = await _seed(db, team_ids=["gl-old"], team_sources={"gl-old": "gitlab"}, team_id="gl-old")

    stored, stages = await _gitlab_sync(db, project, None)

    assert stages == []
    assert stored["team_ids"] == ["gl-old"]


@pytest.mark.asyncio
async def test_a_sync_that_resolved_nothing_retires_its_own_owners_only():
    db = FakeDatabase()
    project = await _seed(
        db,
        team_ids=["gl-old", "by-hand"],
        team_sources={"gl-old": "gitlab", "by-hand": "manual"},
        team_id="gl-old",
    )

    stored, _ = await _gitlab_sync(db, project, [])

    assert stored["team_ids"] == ["by-hand"]
    assert stored["team_sources"] == {"by-hand": "manual"}
    assert stored["team_id"] == "by-hand"
    assert stored["team_source"] == "manual"


@pytest.mark.asyncio
async def test_one_provider_never_touches_the_other_provider_s_owner():
    db = FakeDatabase()
    project = await _seed(
        db,
        team_ids=["gl-a", "gh-a"],
        team_sources={"gl-a": "gitlab", "gh-a": "github"},
        team_id="gl-a",
    )

    stored, _ = await _github_sync(db, project, ["gh-b"])

    assert sorted(stored["team_ids"]) == ["gh-b", "gl-a"]
    assert stored["team_sources"] == {"gl-a": "gitlab", "gh-b": "github"}
    # The incumbent scalar still owns the project, so nothing moves it.
    assert stored["team_id"] == "gl-a"


@pytest.mark.asyncio
async def test_github_attaches_every_team_that_holds_the_repository():
    db = FakeDatabase()
    project = await _seed(db, team_ids=[], team_sources={})

    stored, _ = await _github_sync(db, project, ["gh-b", "gh-a"])

    assert stored["team_ids"] == ["gh-a", "gh-b"]
    assert stored["team_sources"] == {"gh-a": "github", "gh-b": "github"}


@pytest.mark.asyncio
async def test_an_unchanged_subset_is_not_rewritten():
    """Every CI job of every pipeline runs this; re-writing an unchanged owner set is a write
    per ingest for nothing."""
    db = FakeDatabase()
    project = await _seed(
        db,
        team_ids=["gl-a", "by-hand"],
        team_sources={"gl-a": "gitlab", "by-hand": "manual"},
        team_id="gl-a",
    )

    _, stages = await _gitlab_sync(db, project, ["gl-a"])

    assert stages == []


@pytest.mark.asyncio
async def test_a_subset_recorded_but_never_stored_is_written_out():
    """team_sources naming an owner team_ids does not hold is a document an older writer left
    behind; treating it as unchanged would keep it broken forever."""
    db = FakeDatabase()
    project = await _seed(db, team_ids=[], team_sources={"gl-a": "gitlab"})

    stored, stages = await _gitlab_sync(db, project, ["gl-a"])

    assert stages != []
    assert stored["team_ids"] == ["gl-a"]


@pytest.mark.asyncio
async def test_a_legacy_owner_with_no_provenance_is_not_retired_by_a_sync():
    """The branch the per-project provenance gate used to own: an owner predating team_sources.

    It is read as a hand assignment, so a provider adds beside it rather than over it. Naming a
    provider instead would have that provider's next ingest retire an owner on no evidence — and
    218 production projects were in exactly this shape on 2026-09-11.
    """
    db = FakeDatabase()
    project = await _seed(db, team_ids=["legacy"], team_sources={}, team_id="legacy")

    stored, _ = await _gitlab_sync(db, project, ["gl-new"])

    assert sorted(stored["team_ids"]) == ["gl-new", "legacy"]
    assert stored["team_sources"] == {"gl-new": "gitlab"}


@pytest.mark.asyncio
async def test_a_resolution_past_the_cap_leaves_the_owners_alone(caplog):
    db = FakeDatabase()
    project = await _seed(db, team_ids=["gl-a"], team_sources={"gl-a": "gitlab"}, team_id="gl-a")

    with caplog.at_level("WARNING", logger="app.api.deps"):
        stored, stages = await _gitlab_sync(db, project, [f"gl-{n}" for n in range(MAX_PROJECT_TEAMS + 1)])

    assert stages == []
    assert stored["team_ids"] == ["gl-a"]
    assert any("past the cap" in record.getMessage() for record in caplog.records)


@pytest.mark.asyncio
async def test_the_cap_counts_every_owner_and_not_one_provider_s_answer(caplog):
    """A cap that bounds only the resolution lets a full manual roster plus a two-team sync store
    18 owners on a project the routes would have refused a seventeenth."""
    owners = [f"m-{n}" for n in range(MAX_PROJECT_TEAMS)]
    db = FakeDatabase()
    project = await _seed(db, team_ids=owners, team_sources=dict.fromkeys(owners, "manual"))

    with caplog.at_level("WARNING", logger="app.api.deps"):
        stored, stages = await _gitlab_sync(db, project, ["gl-a", "gl-b"])

    assert stages == []
    assert stored["team_ids"] == owners
    assert any("past the cap" in record.getMessage() for record in caplog.records)


@pytest.mark.asyncio
async def test_a_sync_that_stays_inside_the_cap_still_writes():
    owners = [f"m-{n}" for n in range(MAX_PROJECT_TEAMS - 1)]
    db = FakeDatabase()
    project = await _seed(db, team_ids=owners, team_sources=dict.fromkeys(owners, "manual"))

    stored, stages = await _gitlab_sync(db, project, ["gl-a"])

    assert stages != []
    assert sorted(stored["team_ids"]) == sorted([*owners, "gl-a"])


@pytest.mark.asyncio
async def test_the_service_is_asked_about_the_repository_the_token_names():
    db = FakeDatabase()
    project = await _seed(db, team_ids=[], team_sources={})
    service = MagicMock()
    service.sync_team_from_github = AsyncMock(return_value=GitHubTeamSyncResult([]))

    await _github_team_sync_stages(project, "acme-org", "acme/widgets", service, db)

    service.sync_team_from_github.assert_awaited_once_with(db, "acme-org", "acme/widgets")
