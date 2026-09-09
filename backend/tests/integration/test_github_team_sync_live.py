"""One GitHub sync, end to end, against a real database."""

from unittest.mock import AsyncMock, patch

import pytest

from app.models.team import Team, TeamMember
from app.repositories.teams import TeamRepository
from app.services.github import GitHubService, GitHubTeamSyncResult
from tests.mocks.github import make_github_instance

_TEAMS = [
    {"id": 4711, "slug": "payments", "name": "Payments", "permission": "push", "parent": None},
    {"id": 9000, "slug": "platform", "name": "Platform", "permission": "pull", "parent": None},
]


def _service():
    return GitHubService(make_github_instance(id="gh-1", access_token="ghp-secret"))


def _stubbed_reads(service):
    return (
        patch.object(service, "get_repository_teams", new=AsyncMock(return_value=_TEAMS)),
        patch.object(service, "get_org_teams", new=AsyncMock(return_value=_TEAMS)),
        patch.object(
            service, "get_team_members", new=AsyncMock(return_value=[{"login": "ada", "role": "maintainer"}])
        ),
    )


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_a_repository_lands_in_a_github_team_with_its_maintainer_as_admin(db):
    await db["users"].insert_one({"_id": "u-1", "username": "ada", "email": "ada@corp.com"})
    service = _service()
    repo_reads, org_reads, member_reads = _stubbed_reads(service)

    with repo_reads, org_reads, member_reads:
        result = await service.sync_team_from_github(db, "acme", "acme/widgets")

    assert result.candidate_count == 2
    team = await TeamRepository(db).get_raw_by_github_team("gh-1", 4711)
    assert team["_id"] == result.team_id
    assert team["name"] == "GitHub Team: acme/payments"
    assert team["members"] == [{"user_id": "u-1", "role": "admin", "source": "github"}]


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_a_second_sync_merges_into_the_team_it_already_wrote(db):
    await db["users"].insert_one({"_id": "u-1", "username": "ada", "email": "ada@corp.com"})
    repo = TeamRepository(db)
    await repo.create(
        Team(
            id="t-1",
            name="Payments Guild",
            github_instance_id="gh-1",
            github_org="acme",
            github_team_id=4711,
            github_team_slug="pay",
            members=[
                TeamMember(user_id="u-manual", role="admin", source="manual"),
                TeamMember(user_id="u-departed", role="member", source="github"),
            ],
        )
    )
    # Same team number on another instance: the sync must not read or write across the tenant line.
    await repo.create(
        Team(
            id="t-other",
            name="GitHub Team: other/billing",
            github_instance_id="gh-2",
            github_org="other",
            github_team_id=4711,
            github_team_slug="billing",
            members=[TeamMember(user_id="u-other", role="member", source="github")],
        )
    )
    service = _service()
    repo_reads, org_reads, member_reads = _stubbed_reads(service)

    with repo_reads, org_reads, member_reads:
        result = await service.sync_team_from_github(db, "acme", "acme/widgets")

    assert result == GitHubTeamSyncResult("t-1", 2)
    assert await repo.count({}) == 2

    team = await repo.get_raw_by_github_team("gh-1", 4711)
    assert team["name"] == "Payments Guild"
    assert team["github_team_slug"] == "payments"
    assert team["members"] == [
        {"user_id": "u-manual", "role": "admin", "source": "manual"},
        {"user_id": "u-1", "role": "admin", "source": "github"},
    ]

    other = await repo.get_raw_by_github_team("gh-2", 4711)
    assert other["members"] == [{"user_id": "u-other", "role": "member", "source": "github"}]
