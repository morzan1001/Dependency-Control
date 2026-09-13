"""One team, three bound instances, and the member subsets each sync may touch.

A team can hold a binding per instance, of either provider, in any number, and every one of them
refreshes the same ``members`` array. Each sync therefore has to replace exactly the subset its own
instance established — whichever order the three CI runs happen in — or one provider's ingest
quietly launders another's members and nothing refreshes them again.
"""

from itertools import permutations
from unittest.mock import AsyncMock, patch

import pytest

from app.core.constants import TEAM_SOURCE_GITHUB, TEAM_SOURCE_GITLAB, team_source
from app.core.init_db import create_team_indexes
from app.models.gitlab_api import GitLabMember
from app.models.team import GitHubTeamBinding, GitLabGroupBinding, Team
from app.repositories.teams import TeamRepository
from app.services.github import GitHubService
from app.services.gitlab import GitLabService
from tests.mocks.fake_mongo import FakeDatabase
from tests.mocks.github import make_github_instance
from tests.mocks.gitlab import make_gitlab_instance, make_project_details

_GH_A = "gh-inst-a"
_GH_B = "gh-inst-b"
_GL_C = "gl-inst-c"
_SOURCE_GH_A = team_source(TEAM_SOURCE_GITHUB, _GH_A)
_SOURCE_GH_B = team_source(TEAM_SOURCE_GITHUB, _GH_B)
_SOURCE_GL_C = team_source(TEAM_SOURCE_GITLAB, _GL_C)

_TEAM_ID = "t-shared"
_MANUAL = {"user_id": "u-eve", "role": "admin", "source": "manual"}

_ORG_TEAM_A = [{"id": 4711, "slug": "payments", "name": "Payments", "parent": None}]
_ORG_TEAM_B = [{"id": 8150, "slug": "zahlungen", "name": "Zahlungen", "parent": None}]

_USERS = [
    {"_id": "u-ada", "username": "ada", "email": "ada@corp.com"},
    {"_id": "u-bob", "username": "bob", "email": "bob@corp.com"},
    {"_id": "u-cleo", "username": "cleo", "email": "cleo@corp.com"},
    {"_id": "u-eve", "username": "eve", "email": "eve@corp.com"},
]


async def _seed(db) -> None:
    # Cleared first: the order sweep seeds the same estate once per permutation.
    await db.teams.delete_many({})
    await db["users"].delete_many({})
    await create_team_indexes(db)
    for user in _USERS:
        await db["users"].insert_one(dict(user))
    await TeamRepository(db).create(
        Team(
            id=_TEAM_ID,
            name="Payments Guild",
            bindings=[
                GitHubTeamBinding(instance_id=_GH_A, org="acme", external_id=4711, slug="payments"),
                GitHubTeamBinding(instance_id=_GH_B, org="acme", external_id=8150, slug="zahlungen"),
                GitLabGroupBinding(instance_id=_GL_C, external_id=42, path="grp"),
            ],
            members=[dict(_MANUAL)],
        )
    )


async def _github_sync(db, instance_id: str, org_teams: list[dict], logins: list[dict] | None) -> None:
    """One CI run of one GitHub instance against a repository the bound team holds."""
    service = GitHubService(make_github_instance(id=instance_id, access_token="ghp-secret", sync_teams=True))
    with (
        patch.object(service, "get_org_teams", new=AsyncMock(return_value=org_teams)),
        patch.object(service, "get_team_repository", new=AsyncMock(return_value=True)),
        patch.object(service, "get_team_members", new=AsyncMock(return_value=logins)),
        patch.object(service, "get_org_repository_map", new=AsyncMock(return_value={})),
    ):
        await service.sync_team_from_github(db, "acme", "acme/widgets")


async def _gitlab_sync(db, instance_id: str, members: list[GitLabMember] | None) -> None:
    """One CI run of one GitLab instance against a project of the bound group."""
    service = GitLabService(make_gitlab_instance(id=instance_id, sync_teams=True))
    with patch.object(service, "get_group_members", new=AsyncMock(return_value=members)):
        await service.sync_team_from_gitlab(
            db=db,
            gitlab_project_id=100,
            gitlab_project_path="grp/proj",
            gitlab_project_data=make_project_details(namespace_kind="group", namespace_id=42, namespace_path="grp"),
        )


async def _run(db, name: str) -> None:
    if name == _GH_A:
        await _github_sync(db, _GH_A, _ORG_TEAM_A, [{"login": "ada", "role": "maintainer"}])
    elif name == _GH_B:
        await _github_sync(db, _GH_B, _ORG_TEAM_B, [{"login": "bob", "role": "member"}])
    else:
        await _gitlab_sync(db, _GL_C, [GitLabMember(username="cleo", email="cleo@corp.com", access_level=30)])


async def _members(db) -> dict[str, dict]:
    team = await TeamRepository(db).get_raw_by_id(_TEAM_ID)
    return {member["user_id"]: member for member in team["members"]}


async def _assert_every_subset_survives_every_order(db) -> None:
    """The headline: three bound instances, three CI runs, and no order in which one loses a subset."""
    for order in permutations((_GH_A, _GH_B, _GL_C)):
        await _seed(db)

        for name in order:
            await _run(db, name)

        assert await _members(db) == {
            "u-eve": _MANUAL,
            "u-ada": {"user_id": "u-ada", "role": "admin", "source": _SOURCE_GH_A},
            "u-bob": {"user_id": "u-bob", "role": "member", "source": _SOURCE_GH_B},
            "u-cleo": {"user_id": "u-cleo", "role": "member", "source": _SOURCE_GL_C},
        }, f"order {order} lost a subset"


async def _assert_a_second_round_of_runs_changes_nothing(db) -> None:
    await _seed(db)
    for name in (_GH_A, _GH_B, _GL_C):
        await _run(db, name)
    before = await _members(db)

    # The run that a provider-wide source destroys something on.
    for name in (_GL_C, _GH_B, _GH_A):
        await _run(db, name)

    assert await _members(db) == before


async def _assert_a_group_nobody_is_left_in_empties_only_its_own_subset(db) -> None:
    await _seed(db)
    for name in (_GH_A, _GH_B, _GL_C):
        await _run(db, name)

    await _github_sync(db, _GH_A, _ORG_TEAM_A, [])

    assert set(await _members(db)) == {"u-eve", "u-bob", "u-cleo"}


async def _assert_a_failed_fetch_leaves_every_member_alone(db) -> None:
    """The distinction the empty case rests on: None is a question GitHub did not answer."""
    await _seed(db)
    for name in (_GH_A, _GH_B, _GL_C):
        await _run(db, name)
    before = await _members(db)

    await _github_sync(db, _GH_A, _ORG_TEAM_A, None)

    assert await _members(db) == before


@pytest.mark.asyncio
async def test_every_subset_survives_every_order():
    await _assert_every_subset_survives_every_order(FakeDatabase())


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_every_subset_survives_every_order_on_real_mongo(db):
    await _assert_every_subset_survives_every_order(db)


@pytest.mark.asyncio
async def test_a_second_round_of_runs_changes_nothing():
    await _assert_a_second_round_of_runs_changes_nothing(FakeDatabase())


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_a_second_round_of_runs_changes_nothing_on_real_mongo(db):
    await _assert_a_second_round_of_runs_changes_nothing(db)


@pytest.mark.asyncio
async def test_a_group_nobody_is_left_in_empties_only_its_own_subset():
    await _assert_a_group_nobody_is_left_in_empties_only_its_own_subset(FakeDatabase())


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_a_group_nobody_is_left_in_empties_only_its_own_subset_on_real_mongo(db):
    await _assert_a_group_nobody_is_left_in_empties_only_its_own_subset(db)


@pytest.mark.asyncio
async def test_a_failed_fetch_leaves_every_member_alone():
    await _assert_a_failed_fetch_leaves_every_member_alone(FakeDatabase())


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_a_failed_fetch_leaves_every_member_alone_on_real_mongo(db):
    await _assert_a_failed_fetch_leaves_every_member_alone(db)
