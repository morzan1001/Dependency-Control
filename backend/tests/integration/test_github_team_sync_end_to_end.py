"""One GitHub sync, end to end, through the real repositories."""

from unittest.mock import AsyncMock, patch

import pytest

from app.models.team import Team, TeamMember
from app.repositories.teams import TeamRepository
from app.services.github import GitHubService, GitHubTeamRepoAccess, GitHubTeamSyncResult
from tests.mocks.fake_mongo import FakeDatabase
from tests.mocks.github import make_github_instance

_ORG_TEAMS = [
    {"id": 4711, "slug": "payments", "name": "Payments", "parent": None},
    {"id": 9000, "slug": "platform", "name": "Platform", "parent": None},
]

_HOLDS = GitHubTeamRepoAccess(
    True,
    {"role_name": "maintain", "permissions": {"pull": True, "triage": True, "push": True, "maintain": True}},
)


def _service():
    return GitHubService(make_github_instance(id="gh-1", access_token="ghp-secret"))


def _stubbed_reads(service, holders=("payments",)):
    async def _check(_org, team_slug, _owner, _repo):
        return _HOLDS if team_slug in holders else GitHubTeamRepoAccess(False, None)

    return (
        patch.object(service, "get_org_teams", new=AsyncMock(return_value=_ORG_TEAMS)),
        patch.object(service, "get_team_repository", new=AsyncMock(side_effect=_check)),
        patch.object(service, "get_team_members", new=AsyncMock(return_value=[{"login": "ada", "role": "maintainer"}])),
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
    org_reads, check_reads, member_reads = _stubbed_reads(service)

    with org_reads, check_reads, member_reads:
        result = await service.sync_team_from_github(db, "acme", "acme/widgets")

    assert result == GitHubTeamSyncResult("t-1", 1)
    team = await repo.get_raw_by_github_team("gh-1", 4711)
    assert team["name"] == "Payments Guild"
    assert team["github_team_slug"] == "payments"
    assert team["members"] == [{"user_id": "u-1", "role": "admin", "source": "github"}]


async def _assert_an_unbound_github_group_is_not_adopted(db) -> None:
    await db["users"].insert_one({"_id": "u-1", "username": "ada", "email": "ada@corp.com"})
    repo = TeamRepository(db)
    service = _service()
    org_reads, check_reads, member_reads = _stubbed_reads(service, holders=("payments", "platform"))

    with org_reads, check_reads, member_reads:
        result = await service.sync_team_from_github(db, "acme", "acme/widgets")

    assert result == GitHubTeamSyncResult(None, 0)
    assert await repo.count({}) == 0


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
    org_reads, check_reads, member_reads = _stubbed_reads(service)

    with org_reads, check_reads, member_reads:
        result = await service.sync_team_from_github(db, "acme", "acme/widgets")

    assert result == GitHubTeamSyncResult("t-1", 1)
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
    org_reads, check_reads, member_reads = _stubbed_reads(service)

    with org_reads, check_reads, member_reads:
        result = await service.sync_team_from_github(db, "acme", "acme/widgets")

    assert result == GitHubTeamSyncResult("t-1", 1)
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
async def test_a_repository_whose_github_group_nobody_bound_keeps_its_team():
    """The group exists on GitHub and holds the repository; without a binding it is not a team here."""
    await _assert_an_unbound_github_group_is_not_adopted(FakeDatabase())


@pytest.mark.asyncio
async def test_a_second_sync_merges_into_the_team_it_already_wrote():
    await _assert_a_second_sync_merges_into_the_bound_team(FakeDatabase())


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_a_repository_lands_in_the_bound_team_with_its_maintainer_as_admin_on_real_mongo(db):
    await _assert_the_maintainer_lands_in_the_bound_team(db)


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_a_repository_whose_github_group_nobody_bound_keeps_its_team_on_real_mongo(db):
    await _assert_an_unbound_github_group_is_not_adopted(db)


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_a_second_sync_merges_into_the_team_it_already_wrote_on_real_mongo(db):
    await _assert_a_second_sync_merges_into_the_bound_team(db)
