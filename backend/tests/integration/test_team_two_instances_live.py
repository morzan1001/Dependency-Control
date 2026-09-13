"""One team bound to two instances of one provider, through the real repositories and a real server.

This is what the per-instance binding is for. Each instance's ingest must resolve the team through
its own binding, own its own projects, and leave the other instance's binding and owners alone —
including on the second CI run, which is where a provider-wide binding first destroys something.
"""

from unittest.mock import AsyncMock, patch

import pytest

from app.api.deps import _github_team_sync_stages
from app.core.constants import TEAM_SOURCE_GITHUB, team_source
from app.core.init_db import create_team_indexes
from app.models.project import Project
from app.models.team import GitHubTeamBinding, Team
from app.repositories.projects import ProjectRepository
from app.repositories.teams import TeamRepository
from app.services.github import GitHubService
from tests.mocks.fake_mongo import FakeDatabase
from tests.mocks.github import make_github_instance

_A = "gh-inst-a"
_B = "gh-inst-b"
_SOURCE_A = team_source(TEAM_SOURCE_GITHUB, _A)
_SOURCE_B = team_source(TEAM_SOURCE_GITHUB, _B)

_TEAMS_A = [{"id": 4711, "slug": "payments", "name": "Payments", "parent": None}]
_TEAMS_B = [{"id": 8150, "slug": "zahlungen", "name": "Zahlungen", "parent": None}]


def _service(instance_id: str) -> GitHubService:
    return GitHubService(make_github_instance(id=instance_id, access_token="ghp-secret", sync_teams=True))


def _reads(service: GitHubService, org_teams: list[dict]):
    """Every read the resolution makes, answered as GitHub would for a group that holds the repository."""
    return (
        patch.object(service, "get_org_teams", new=AsyncMock(return_value=org_teams)),
        patch.object(service, "get_team_repository", new=AsyncMock(return_value=True)),
        patch.object(
            service, "get_team_members", new=AsyncMock(return_value=[{"login": "ada", "role": "maintainer"}])
        ),
        patch.object(service, "get_org_repository_map", new=AsyncMock(return_value={})),
    )


async def _ingest(db, instance_id: str, org_teams: list[dict], project_id: str, path: str) -> Project:
    """One CI run of one instance against one of its projects."""
    project_repo = ProjectRepository(db)
    project = await project_repo.get_by_id(project_id)
    service = _service(instance_id)
    org_reads, check_reads, member_reads, map_reads = _reads(service, org_teams)

    with org_reads, check_reads, member_reads, map_reads:
        stages = await _github_team_sync_stages(project, instance_id, "acme", path, service, db)

    if stages:
        await project_repo.update_raw(project_id, stages)
    return await project_repo.get_by_id(project_id)


async def _seed(db) -> None:
    await create_team_indexes(db)
    await db["users"].insert_one({"_id": "u-ada", "username": "ada", "email": "ada@corp.com"})
    await TeamRepository(db).create(
        Team(
            id="t-shared",
            name="Payments Guild",
            bindings=[
                GitHubTeamBinding(instance_id=_A, org="acme", external_id=4711, slug="payments"),
                GitHubTeamBinding(instance_id=_B, org="acme", external_id=8150, slug="zahlungen"),
            ],
        )
    )
    for project_id, instance_id in (("p-a", _A), ("p-b", _B)):
        await db.projects.insert_one(
            Project(
                id=project_id,
                name=f"acme/{project_id}",
                github_instance_id=instance_id,
                github_repository_id="1",
                github_repository_path=f"acme/{project_id}",
            ).model_dump(by_alias=True)
        )


async def _assert_each_instance_owns_its_own_projects_through_one_team(db) -> None:
    await _seed(db)

    after_a = await _ingest(db, _A, _TEAMS_A, "p-a", "acme/p-a")
    after_b = await _ingest(db, _B, _TEAMS_B, "p-b", "acme/p-b")

    assert after_a.team_ids == ["t-shared"]
    assert after_a.team_sources == {"t-shared": _SOURCE_A}
    assert after_b.team_ids == ["t-shared"]
    assert after_b.team_sources == {"t-shared": _SOURCE_B}


async def _assert_a_second_run_disturbs_neither_the_other_binding_nor_its_owners(db) -> None:
    await _seed(db)
    await _ingest(db, _A, _TEAMS_A, "p-a", "acme/p-a")
    await _ingest(db, _B, _TEAMS_B, "p-b", "acme/p-b")

    # The run that a provider-wide binding would have destroyed something on.
    await _ingest(db, _A, _TEAMS_A, "p-a", "acme/p-a")
    await _ingest(db, _B, _TEAMS_B, "p-b", "acme/p-b")

    project_repo = ProjectRepository(db)
    assert (await project_repo.get_by_id("p-a")).team_sources == {"t-shared": _SOURCE_A}
    assert (await project_repo.get_by_id("p-b")).team_sources == {"t-shared": _SOURCE_B}

    team = await TeamRepository(db).get_raw_by_id("t-shared")
    assert sorted(binding["key"] for binding in team["bindings"]) == [
        f"github:{_A}:4711",
        f"github:{_B}:8150",
    ]
    # Each instance resolved the same person; the entry names whichever synced last, and one entry
    # is what matters — two would break add_member's $ne guard.
    assert team["members"] == [{"user_id": "u-ada", "role": "admin", "source": _SOURCE_B}]


async def _assert_a_rename_on_one_instance_leaves_the_other_binding_alone(db) -> None:
    """The display fields sit inside the binding, so a slug restamp addresses one instance's entry."""
    await _seed(db)

    await _ingest(db, _A, [{"id": 4711, "slug": "pay-renamed", "name": "Payments", "parent": None}], "p-a", "acme/p-a")

    team = await TeamRepository(db).get_raw_by_id("t-shared")
    assert {binding["instance_id"]: binding["slug"] for binding in team["bindings"]} == {
        _A: "pay-renamed",
        _B: "zahlungen",
    }


async def _assert_one_instance_resolves_only_through_its_own_binding(db) -> None:
    """The team is bound on B only. A's ingest must find nothing rather than read B's binding as
    its own and hand A's repository to a team no group of A's holds."""
    await create_team_indexes(db)
    await db["users"].insert_one({"_id": "u-ada", "username": "ada", "email": "ada@corp.com"})
    await TeamRepository(db).create(
        Team(
            id="t-b-only",
            name="Zahlungen",
            bindings=[GitHubTeamBinding(instance_id=_B, org="acme", external_id=8150, slug="zahlungen")],
        )
    )
    await db.projects.insert_one(
        Project(
            id="p-a",
            name="acme/p-a",
            github_instance_id=_A,
            github_repository_id="1",
            github_repository_path="acme/p-a",
        ).model_dump(by_alias=True)
    )

    after_a = await _ingest(db, _A, _TEAMS_A, "p-a", "acme/p-a")

    assert after_a.team_ids == []
    assert (await TeamRepository(db).get_raw_by_id("t-b-only"))["bindings"][0]["instance_id"] == _B


@pytest.mark.asyncio
async def test_each_instance_owns_its_own_projects_through_one_team():
    await _assert_each_instance_owns_its_own_projects_through_one_team(FakeDatabase())


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_each_instance_owns_its_own_projects_through_one_team_on_real_mongo(db):
    await _assert_each_instance_owns_its_own_projects_through_one_team(db)


@pytest.mark.asyncio
async def test_a_second_run_disturbs_neither_the_other_binding_nor_its_owners():
    await _assert_a_second_run_disturbs_neither_the_other_binding_nor_its_owners(FakeDatabase())


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_a_second_run_disturbs_neither_the_other_binding_nor_its_owners_on_real_mongo(db):
    await _assert_a_second_run_disturbs_neither_the_other_binding_nor_its_owners(db)


@pytest.mark.asyncio
async def test_a_rename_on_one_instance_leaves_the_other_binding_alone():
    await _assert_a_rename_on_one_instance_leaves_the_other_binding_alone(FakeDatabase())


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_a_rename_on_one_instance_leaves_the_other_binding_alone_on_real_mongo(db):
    await _assert_a_rename_on_one_instance_leaves_the_other_binding_alone(db)


@pytest.mark.asyncio
async def test_one_instance_resolves_only_through_its_own_binding():
    await _assert_one_instance_resolves_only_through_its_own_binding(FakeDatabase())


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_one_instance_resolves_only_through_its_own_binding_on_real_mongo(db):
    await _assert_one_instance_resolves_only_through_its_own_binding(db)
