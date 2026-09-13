"""One GitHub sync, end to end, through the real repositories."""

from unittest.mock import AsyncMock, patch

import pytest

from app.models.team import Team, TeamMember
from app.repositories.teams import TeamRepository
from app.services.github import GitHubService, GitHubTeamSyncResult
from tests.mocks.fake_mongo import FakeDatabase
from tests.mocks.github import make_github_instance

_ORG_TEAMS = [
    {"id": 4711, "slug": "payments", "name": "Payments", "parent": None},
    {"id": 9000, "slug": "platform", "name": "Platform", "parent": None},
]

def _service(*, sync_teams=False):
    return GitHubService(make_github_instance(id="gh-1", access_token="ghp-secret", sync_teams=sync_teams))


def _stubbed_reads(service, holders=("payments",), repo_map=None, org_teams=None):
    async def _check(_org, team_slug, _owner, _repo):
        return team_slug in holders

    return (
        patch.object(service, "get_org_teams", new=AsyncMock(return_value=org_teams or _ORG_TEAMS)),
        patch.object(service, "get_team_repository", new=AsyncMock(side_effect=_check)),
        patch.object(service, "get_team_members", new=AsyncMock(return_value=[{"login": "ada", "role": "maintainer"}])),
        patch.object(service, "get_org_repository_map", new=AsyncMock(return_value=repo_map or {})),
    )


def _bound_team(**overrides) -> Team:
    fields = {
        "id": "t-1",
        "name": "Payments Guild",
        "github_instance_id": "gh-1",
        "github_org": "acme",
        "github_team_id": 4711,
        "github_team_slug": "payments",
        "members": [],
    }
    fields.update(overrides)
    return Team(**fields)


async def _assert_the_maintainer_lands_in_the_bound_team(db) -> None:
    await db["users"].insert_one({"_id": "u-1", "username": "ada", "email": "ada@corp.com"})
    repo = TeamRepository(db)
    await repo.create(_bound_team(github_team_slug="pay-old"))
    service = _service()
    org_reads, check_reads, member_reads, map_reads = _stubbed_reads(service)

    with org_reads, check_reads, member_reads, map_reads:
        result = await service.sync_team_from_github(db, "acme", "acme/widgets")

    assert result == GitHubTeamSyncResult(["t-1"])
    team = await repo.get_raw_by_github_team("gh-1", 4711)
    assert team["name"] == "Payments Guild"
    assert team["github_team_slug"] == "payments"
    assert team["members"] == [{"user_id": "u-1", "role": "admin", "source": "github"}]


_HELD_BY_PLATFORM = {"acme/widgets": [9000]}


async def _assert_an_unbound_github_group_becomes_a_team(db) -> None:
    await db["users"].insert_one({"_id": "u-1", "username": "ada", "email": "ada@corp.com"})
    repo = TeamRepository(db)
    service = _service(sync_teams=True)
    org_reads, check_reads, member_reads, map_reads = _stubbed_reads(service, holders=(), repo_map=_HELD_BY_PLATFORM)

    with org_reads, check_reads, member_reads, map_reads:
        result = await service.sync_team_from_github(db, "acme", "acme/widgets")

    assert await repo.count({}) == 1
    team = await repo.get_raw_by_github_team("gh-1", 9000)
    assert result == GitHubTeamSyncResult([team["_id"]])
    assert team["name"] == "GitHub Team: acme/platform"
    assert (team["github_org"], team["github_team_slug"]) == ("acme", "platform")
    assert team["members"] == [{"user_id": "u-1", "role": "admin", "source": "github"}]


async def _assert_the_group_is_not_created_twice(db) -> None:
    """Once created the team is bound, so the next scan resolves it through the direct check and
    the map only confirms that nothing else has been granted access since."""
    await db["users"].insert_one({"_id": "u-1", "username": "ada", "email": "ada@corp.com"})
    repo = TeamRepository(db)
    service = _service(sync_teams=True)
    org_reads, check_reads, member_reads, map_reads = _stubbed_reads(
        service, holders=("platform",), repo_map=_HELD_BY_PLATFORM
    )

    with org_reads, check_reads, member_reads, map_reads:
        first = await service.sync_team_from_github(db, "acme", "acme/widgets")
        second = await service.sync_team_from_github(db, "acme", "acme/widgets")

    assert await repo.count({}) == 1
    assert second == first


async def _assert_a_team_of_the_same_name_is_adopted(db) -> None:
    """The four groups this matched in production are teams the owner has under their own name."""
    await db["users"].insert_one({"_id": "u-1", "username": "ada", "email": "ada@corp.com"})
    repo = TeamRepository(db)
    await repo.create(Team(id="t-llama", name="Shangri Llama"))
    service = _service(sync_teams=True)
    org_teams = [{"id": 9000, "slug": "team-shangri-llama", "name": "team-shangri-llama", "parent": None}]
    org_reads, check_reads, member_reads, map_reads = _stubbed_reads(
        service, holders=(), repo_map=_HELD_BY_PLATFORM, org_teams=org_teams
    )

    with org_reads, check_reads, member_reads, map_reads:
        result = await service.sync_team_from_github(db, "acme", "acme/widgets")

    assert result == GitHubTeamSyncResult(["t-llama"])
    assert await repo.count({}) == 1
    adopted = await repo.get_raw_by_github_team("gh-1", 9000)
    assert adopted["_id"] == "t-llama"
    assert adopted["name"] == "Shangri Llama"
    assert adopted["github_team_slug"] == "team-shangri-llama"
    assert adopted["members"] == [{"user_id": "u-1", "role": "admin", "source": "github"}]


async def _sync_against_the_existing_team(db, existing: Team) -> tuple[GitHubTeamSyncResult, TeamRepository]:
    repo = TeamRepository(db)
    await repo.create(existing)
    service = _service(sync_teams=True)
    org_reads, check_reads, member_reads, map_reads = _stubbed_reads(service, holders=(), repo_map=_HELD_BY_PLATFORM)

    with org_reads, check_reads, member_reads, map_reads:
        return await service.sync_team_from_github(db, "acme", "acme/widgets"), repo


async def _assert_a_team_bound_to_another_instance_is_not_stolen(db) -> None:
    """Two instances are two tenants, and the same name on both is two different teams."""
    result, repo = await _sync_against_the_existing_team(
        db,
        Team(
            id="t-elsewhere",
            name="Platform",
            github_instance_id="gh-2",
            github_org="other",
            github_team_id=1234,
            github_team_slug="platform",
        ),
    )

    created = await repo.get_raw_by_github_team("gh-1", 9000)
    assert created["name"] == "GitHub Team: acme/platform"
    assert result == GitHubTeamSyncResult([created["_id"]])

    untouched = await repo.get_raw_by_github_team("gh-2", 1234)
    assert (untouched["_id"], untouched["github_org"], untouched["github_team_id"]) == ("t-elsewhere", "other", 1234)


async def _assert_a_team_synced_from_gitlab_is_not_adopted(db) -> None:
    """Both syncs replace the member subset they own; one team fed by two would never settle."""
    result, repo = await _sync_against_the_existing_team(
        db, Team(id="t-gitlab", name="Platform", gitlab_instance_id="gl-1", gitlab_group_id=77)
    )

    created = await repo.get_raw_by_github_team("gh-1", 9000)
    assert created["name"] == "GitHub Team: acme/platform"
    assert result == GitHubTeamSyncResult([created["_id"]])

    untouched = await repo.get_raw_by_id("t-gitlab")
    assert (untouched["github_team_id"], untouched["gitlab_group_id"]) == (None, 77)


async def _assert_an_unbound_github_group_is_not_adopted(db) -> None:
    """Creation follows the instance's switch, as it does on GitLab. The bound team holding nothing
    is what carries the resolution past the shortcut for an organisation with no binding at all."""
    repo = TeamRepository(db)
    await repo.create(_bound_team())
    service = _service()
    org_reads, check_reads, member_reads, map_reads = _stubbed_reads(
        service, holders=(), repo_map=_HELD_BY_PLATFORM
    )

    with org_reads, check_reads, member_reads, map_reads:
        result = await service.sync_team_from_github(db, "acme", "acme/widgets")

    assert result == GitHubTeamSyncResult([])
    assert await repo.count({}) == 1


async def _assert_a_second_sync_merges_into_the_bound_team(db) -> None:
    await db["users"].insert_one({"_id": "u-1", "username": "ada", "email": "ada@corp.com"})
    repo = TeamRepository(db)
    await repo.create(
        _bound_team(
            members=[
                TeamMember(user_id="u-manual", role="admin", source="manual"),
                TeamMember(user_id="u-departed", role="member", source="github"),
            ]
        )
    )
    # Same team number on another instance: the sync must not read or write across the tenant line.
    await repo.create(
        Team(
            id="t-other",
            name="Billing",
            github_instance_id="gh-2",
            github_org="acme",
            github_team_id=4711,
            github_team_slug="payments",
            members=[TeamMember(user_id="u-other", role="member", source="github")],
        )
    )
    service = _service()
    org_reads, check_reads, member_reads, map_reads = _stubbed_reads(service)

    with org_reads, check_reads, member_reads, map_reads:
        result = await service.sync_team_from_github(db, "acme", "acme/widgets")

    assert result == GitHubTeamSyncResult(["t-1"])
    assert await repo.count({}) == 2

    team = await repo.get_raw_by_github_team("gh-1", 4711)
    assert team["members"] == [
        {"user_id": "u-manual", "role": "admin", "source": "manual"},
        {"user_id": "u-1", "role": "admin", "source": "github"},
    ]

    other = await repo.get_raw_by_github_team("gh-2", 4711)
    assert other["members"] == [{"user_id": "u-other", "role": "member", "source": "github"}]


async def _assert_the_organisation_case_does_not_decide(db) -> None:
    """The OIDC claim is lower-case; a binding stored in GitHub's own spelling must still match."""
    await db["users"].insert_one({"_id": "u-1", "username": "ada", "email": "ada@corp.com"})
    repo = TeamRepository(db)
    await repo.create(_bound_team(github_org="Acme"))
    service = _service()
    org_reads, check_reads, member_reads, map_reads = _stubbed_reads(service)

    with org_reads, check_reads, member_reads, map_reads:
        result = await service.sync_team_from_github(db, "acme", "acme/widgets")

    assert result == GitHubTeamSyncResult(["t-1"])
    team = await repo.get_raw_by_github_team("gh-1", 4711)
    assert team["members"] == [{"user_id": "u-1", "role": "admin", "source": "github"}]


@pytest.mark.asyncio
async def test_a_repository_lands_in_the_bound_team_with_its_maintainer_as_admin():
    await _assert_the_maintainer_lands_in_the_bound_team(FakeDatabase())


@pytest.mark.asyncio
async def test_a_binding_stored_in_another_case_still_resolves():
    await _assert_the_organisation_case_does_not_decide(FakeDatabase())


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_a_binding_stored_in_another_case_still_resolves_on_real_mongo(db):
    await _assert_the_organisation_case_does_not_decide(db)


@pytest.mark.asyncio
async def test_a_repository_whose_github_group_nobody_bound_gains_that_group_as_a_team():
    await _assert_an_unbound_github_group_becomes_a_team(FakeDatabase())


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_a_repository_whose_github_group_nobody_bound_gains_that_group_as_a_team_on_real_mongo(db):
    await _assert_an_unbound_github_group_becomes_a_team(db)


@pytest.mark.asyncio
async def test_a_group_already_created_is_adopted_rather_than_created_again():
    await _assert_the_group_is_not_created_twice(FakeDatabase())


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_a_group_already_created_is_adopted_rather_than_created_again_on_real_mongo(db):
    await _assert_the_group_is_not_created_twice(db)


@pytest.mark.asyncio
async def test_a_repository_whose_github_group_nobody_bound_gains_no_owner_while_creation_is_off():
    await _assert_an_unbound_github_group_is_not_adopted(FakeDatabase())


@pytest.mark.asyncio
async def test_a_group_whose_team_already_exists_under_its_own_name_is_adopted():
    await _assert_a_team_of_the_same_name_is_adopted(FakeDatabase())


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_a_group_whose_team_already_exists_under_its_own_name_is_adopted_on_real_mongo(db):
    await _assert_a_team_of_the_same_name_is_adopted(db)


@pytest.mark.asyncio
async def test_a_team_bound_to_another_instance_is_not_adopted():
    await _assert_a_team_bound_to_another_instance_is_not_stolen(FakeDatabase())


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_a_team_bound_to_another_instance_is_not_adopted_on_real_mongo(db):
    await _assert_a_team_bound_to_another_instance_is_not_stolen(db)


@pytest.mark.asyncio
async def test_a_team_gitlab_already_syncs_is_not_adopted():
    await _assert_a_team_synced_from_gitlab_is_not_adopted(FakeDatabase())


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_a_team_gitlab_already_syncs_is_not_adopted_on_real_mongo(db):
    await _assert_a_team_synced_from_gitlab_is_not_adopted(db)


@pytest.mark.asyncio
async def test_a_second_sync_merges_into_the_team_it_already_wrote():
    await _assert_a_second_sync_merges_into_the_bound_team(FakeDatabase())


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_a_repository_lands_in_the_bound_team_with_its_maintainer_as_admin_on_real_mongo(db):
    await _assert_the_maintainer_lands_in_the_bound_team(db)


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_a_repository_whose_github_group_nobody_bound_gains_no_owner_while_creation_is_off_on_real_mongo(db):
    await _assert_an_unbound_github_group_is_not_adopted(db)


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_a_second_sync_merges_into_the_team_it_already_wrote_on_real_mongo(db):
    await _assert_a_second_sync_merges_into_the_bound_team(db)
