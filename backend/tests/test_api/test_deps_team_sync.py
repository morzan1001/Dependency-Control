"""Each case applies the produced stages and asserts the stored result, since inspecting stages alone proves nothing."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from app.api.deps import _CiClaim, _GitHubCi, _GitLabCi, _ownership_stages
from app.core.constants import (
    GITLAB_TEAM_SYNC_WINDOW_SECONDS,
    MAX_PROJECT_TEAMS,
    TEAM_SOURCE_GITHUB,
    TEAM_SOURCE_GITLAB,
    team_source,
)
from app.models.project import Project
from app.models.team import TeamSyncResult
from app.repositories.projects import ProjectRepository
from tests.mocks.fake_mongo import FakeDatabase
from tests.mocks.github import make_github_instance
from tests.mocks.gitlab import make_gitlab_instance

_PROJECT_ID = "p-1"
_GITLAB_INSTANCE = "inst-1"
_GITHUB_INSTANCE = "gh-1"
_SECOND_GITLAB_INSTANCE = "inst-2"
_GITLAB = team_source(TEAM_SOURCE_GITLAB, _GITLAB_INSTANCE)
_SECOND_GITLAB = team_source(TEAM_SOURCE_GITLAB, _SECOND_GITLAB_INSTANCE)
_GITHUB = team_source(TEAM_SOURCE_GITHUB, _GITHUB_INSTANCE)
_GITLAB_CLAIM = _CiClaim(100, "grp/proj", None)
_GITHUB_CLAIM = _CiClaim("123456", "acme/widgets", "ada")


async def _seed(db, **ownership) -> Project:
    doc = {
        "_id": _PROJECT_ID,
        "name": "grp/proj",
        "gitlab_instance_id": _GITLAB_INSTANCE,
        "gitlab_project_id": 100,
        "github_instance_id": _GITHUB_INSTANCE,
        "github_repository_id": "123456",
        **ownership,
    }
    await db.projects.insert_one(doc)
    return Project(**doc)


def _gitlab(service, instance_id: str = _GITLAB_INSTANCE) -> _GitLabCi:
    service.instance, service.team_provider = make_gitlab_instance(id=instance_id), TEAM_SOURCE_GITLAB
    service.instance_id, service.member_source = instance_id, team_source(TEAM_SOURCE_GITLAB, instance_id)
    return _GitLabCi(service)


def _github(service) -> _GitHubCi:
    service.instance, service.team_provider = make_github_instance(id=_GITHUB_INSTANCE), TEAM_SOURCE_GITHUB
    service.instance_id, service.member_source = _GITHUB_INSTANCE, _GITHUB
    return _GitHubCi(service)


async def _apply(db, project: Project, stages: list[dict]) -> dict:
    if stages:
        await ProjectRepository(db).update_raw(str(project.id), stages)
    return await db.projects.find_one({"_id": str(project.id)})


async def _gitlab_sync(
    db, project: Project, resolved: list[str] | None, instance_id: str = _GITLAB_INSTANCE
) -> tuple[dict, list[dict]]:
    service = MagicMock()
    service.sync_team_from_gitlab = AsyncMock(return_value=TeamSyncResult(resolved))
    stages = await _ownership_stages(_gitlab(service, instance_id), project, _GITLAB_CLAIM, db)
    return await _apply(db, project, stages), stages


async def _github_sync(db, project: Project, resolved: list[str] | None) -> tuple[dict, list[dict]]:
    service = MagicMock()
    service.sync_team_from_github = AsyncMock(return_value=TeamSyncResult(resolved))
    stages = await _ownership_stages(_github(service), project, _GITHUB_CLAIM, db)
    return await _apply(db, project, stages), stages


@pytest.mark.asyncio
async def test_a_sync_does_not_evict_a_manual_co_owner():
    """A CI ingest runs on every pipeline, so a blind replace would delete an operator's assignment within minutes."""
    db = FakeDatabase()
    project = await _seed(
        db,
        team_ids=["gl-old", "by-hand"],
        team_sources={"gl-old": _GITLAB, "by-hand": "manual"},
    )

    stored, _ = await _gitlab_sync(db, project, ["gl-new"])

    assert sorted(stored["team_ids"]) == ["by-hand", "gl-new"]
    assert stored["team_sources"] == {"by-hand": "manual", "gl-new": _GITLAB}


@pytest.mark.asyncio
async def test_a_project_that_moved_group_loses_the_owner_it_left():
    """A union would keep the old group forever, so every transfer would widen access instead of moving it."""
    db = FakeDatabase()
    project = await _seed(db, team_ids=["gl-old"], team_sources={"gl-old": _GITLAB})

    stored, _ = await _gitlab_sync(db, project, ["gl-new"])

    assert stored["team_ids"] == ["gl-new"]
    assert stored["team_sources"] == {"gl-new": _GITLAB}


@pytest.mark.asyncio
async def test_a_sync_that_could_not_be_asked_writes_nothing():
    db = FakeDatabase()
    project = await _seed(db, team_ids=["gl-old"], team_sources={"gl-old": _GITLAB})

    stored, stages = await _gitlab_sync(db, project, None)

    assert stages == []
    assert stored["team_ids"] == ["gl-old"]


@pytest.mark.asyncio
async def test_a_sync_that_resolved_nothing_retires_its_own_owners_only():
    db = FakeDatabase()
    project = await _seed(
        db,
        team_ids=["gl-old", "by-hand"],
        team_sources={"gl-old": _GITLAB, "by-hand": "manual"},
    )

    stored, _ = await _gitlab_sync(db, project, [])

    assert stored["team_ids"] == ["by-hand"]
    assert stored["team_sources"] == {"by-hand": "manual"}


@pytest.mark.asyncio
async def test_one_provider_never_touches_the_other_provider_s_owner():
    db = FakeDatabase()
    project = await _seed(
        db,
        team_ids=["gl-a", "gh-a"],
        team_sources={"gl-a": _GITLAB, "gh-a": _GITHUB},
    )

    stored, _ = await _github_sync(db, project, ["gh-b"])

    assert sorted(stored["team_ids"]) == ["gh-b", "gl-a"]
    assert stored["team_sources"] == {"gl-a": _GITLAB, "gh-b": _GITHUB}


@pytest.mark.asyncio
async def test_one_gitlab_instance_never_touches_another_gitlab_instance_s_owner():
    """A provider-wide source would make two instances retire each other's team in turn on every CI run."""
    db = FakeDatabase()
    project = await _seed(
        db,
        team_ids=["gl-a", "gl-b"],
        team_sources={"gl-a": _GITLAB, "gl-b": _SECOND_GITLAB},
    )

    stored, _ = await _gitlab_sync(db, project, ["gl-b-moved"], instance_id=_SECOND_GITLAB_INSTANCE)

    assert sorted(stored["team_ids"]) == ["gl-a", "gl-b-moved"]
    assert stored["team_sources"] == {"gl-a": _GITLAB, "gl-b-moved": _SECOND_GITLAB}


@pytest.mark.asyncio
async def test_github_attaches_every_team_that_holds_the_repository():
    db = FakeDatabase()
    project = await _seed(db, team_ids=[], team_sources={})

    stored, _ = await _github_sync(db, project, ["gh-b", "gh-a"])

    assert stored["team_ids"] == ["gh-a", "gh-b"]
    assert stored["team_sources"] == {"gh-a": _GITHUB, "gh-b": _GITHUB}


@pytest.mark.asyncio
async def test_an_unchanged_subset_is_not_rewritten():
    """Every CI job runs this, so rewriting an unchanged owner set would be a write per ingest for nothing."""
    db = FakeDatabase()
    project = await _seed(
        db,
        team_ids=["gl-a", "by-hand"],
        team_sources={"gl-a": _GITLAB, "by-hand": "manual"},
    )

    _, stages = await _gitlab_sync(db, project, ["gl-a"])

    assert stages == []


@pytest.mark.asyncio
async def test_a_subset_recorded_but_never_stored_is_written_out():
    """Older writers left team_sources naming an owner team_ids lacks; skipping those keeps them broken."""
    db = FakeDatabase()
    project = await _seed(db, team_ids=[], team_sources={"gl-a": _GITLAB})

    stored, stages = await _gitlab_sync(db, project, ["gl-a"])

    assert stages != []
    assert stored["team_ids"] == ["gl-a"]


@pytest.mark.asyncio
async def test_a_legacy_owner_with_no_provenance_is_not_retired_by_a_sync():
    """An owner predating team_sources reads as a hand assignment, so a provider adds beside it rather than over it."""
    db = FakeDatabase()
    project = await _seed(db, team_ids=["legacy"], team_sources={})

    stored, _ = await _gitlab_sync(db, project, ["gl-new"])

    assert sorted(stored["team_ids"]) == ["gl-new", "legacy"]
    assert stored["team_sources"] == {"gl-new": _GITLAB}


@pytest.mark.asyncio
async def test_a_resolution_past_the_cap_leaves_the_owners_alone(caplog):
    db = FakeDatabase()
    project = await _seed(db, team_ids=["gl-a"], team_sources={"gl-a": _GITLAB})

    with caplog.at_level("WARNING", logger="app.api.deps"):
        stored, stages = await _gitlab_sync(db, project, [f"gl-{n}" for n in range(MAX_PROJECT_TEAMS + 1)])

    assert stages == []
    assert stored["team_ids"] == ["gl-a"]
    assert any("past the cap" in record.getMessage() for record in caplog.records)


@pytest.mark.asyncio
async def test_the_cap_counts_every_owner_and_not_one_provider_s_answer(caplog):
    """A cap on the resolution alone would let a full manual roster plus a two-team sync exceed the routes' limit."""
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
    service.sync_team_from_github = AsyncMock(return_value=TeamSyncResult([]))

    await _ownership_stages(_github(service), project, _GITHUB_CLAIM, db)

    service.sync_team_from_github.assert_awaited_once_with(
        db, "acme/widgets", current_owner_ids=set(), owner_budget=MAX_PROJECT_TEAMS
    )


@pytest.mark.asyncio
async def test_the_provider_is_told_which_owners_it_replaces_and_how_much_room_is_left():
    """GitHub creates the teams it names, so a resolution refused afterwards would leave those teams owning nothing."""
    db = FakeDatabase()
    others = [f"m-{n}" for n in range(4)]
    project = await _seed(
        db,
        team_ids=[*others, "gh-a"],
        team_sources={**dict.fromkeys(others, "manual"), "gh-a": _GITHUB},
    )
    service = MagicMock()
    service.sync_team_from_github = AsyncMock(return_value=TeamSyncResult(["gh-a"]))

    await _ownership_stages(_github(service), project, _GITHUB_CLAIM, db)

    assert service.sync_team_from_github.await_args.kwargs == {
        "current_owner_ids": {"gh-a"},
        "owner_budget": MAX_PROJECT_TEAMS - 4,
    }


@pytest.mark.asyncio
async def test_gitlab_reads_the_project_itself_and_is_told_how_much_room_is_left():
    db = FakeDatabase()
    others = [f"m-{n}" for n in range(4)]
    project = await _seed(
        db,
        team_ids=[*others, "gl-a"],
        team_sources={**dict.fromkeys(others, "manual"), "gl-a": _GITLAB},
    )
    service = MagicMock()
    service.sync_team_from_gitlab = AsyncMock(return_value=TeamSyncResult(["gl-a"]))

    await _ownership_stages(_gitlab(service), project, _GITLAB_CLAIM, db)

    service.sync_team_from_gitlab.assert_awaited_once_with(db, 100, "grp/proj", owner_budget=MAX_PROJECT_TEAMS - 4)
    service.get_project_details.assert_not_called()


@pytest.mark.asyncio
async def test_a_hand_assigned_owner_the_sync_also_resolves_survives_its_later_loss():
    """The picker is the only writer that may take a hand assignment away."""
    db = FakeDatabase()
    project = await _seed(db, team_ids=["platform"], team_sources={"platform": "manual"})

    _, stages = await _github_sync(db, project, ["platform"])
    stored, _ = await _github_sync(db, Project(**await db.projects.find_one({"_id": _PROJECT_ID})), [])

    assert stages == []
    assert stored["team_ids"] == ["platform"]
    assert stored["team_sources"] == {"platform": "manual"}


async def _resolutions(cache, monkeypatch, ingests: int) -> int:
    monkeypatch.setattr("app.api.deps.cache_service", cache, raising=False)
    db = FakeDatabase()
    project = await _seed(db, team_ids=["gl-old"], team_sources={"gl-old": _GITLAB})
    service = MagicMock()
    service.sync_team_from_gitlab = AsyncMock(return_value=TeamSyncResult(["gl-new"]))
    for _ in range(ingests):
        await _ownership_stages(_gitlab(service), project, _GITLAB_CLAIM, db)
    return service.sync_team_from_gitlab.await_count


@pytest.mark.asyncio
async def test_the_ingests_of_one_window_resolve_gitlab_ownership_once(fake_cache, monkeypatch):
    assert await _resolutions(fake_cache, monkeypatch, ingests=3) == 1
    window = await fake_cache._client.ttl(fake_cache._make_key(f"gitlab_team_sync:{_GITLAB}:100"))
    assert 0 < window <= GITLAB_TEAM_SYNC_WINDOW_SECONDS


@pytest.mark.asyncio
async def test_every_ingest_resolves_gitlab_ownership_while_the_cache_is_down(monkeypatch):
    assert await _resolutions(MagicMock(incr=AsyncMock(return_value=None)), monkeypatch, ingests=2) == 2
