"""One GitHub sync, end to end, against a real database."""

from unittest.mock import AsyncMock, patch

import pytest

from app.repositories.teams import TeamRepository
from app.services.github import GitHubService
from tests.mocks.github import make_github_instance

_TEAMS = [
    {"id": 4711, "slug": "payments", "name": "Payments", "permission": "push", "parent": None},
    {"id": 9000, "slug": "platform", "name": "Platform", "permission": "pull", "parent": None},
]


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_a_repository_lands_in_a_github_team_with_its_maintainer_as_admin(db):
    await db["users"].insert_one({"_id": "u-1", "username": "ada", "email": "ada@corp.com"})
    service = GitHubService(make_github_instance(id="gh-1", access_token="ghp-secret"))

    with (
        patch.object(service, "get_repository_teams", new=AsyncMock(return_value=_TEAMS)),
        patch.object(service, "get_org_teams", new=AsyncMock(return_value=_TEAMS)),
        patch.object(
            service, "get_team_members", new=AsyncMock(return_value=[{"login": "ada", "role": "maintainer"}])
        ),
    ):
        result = await service.sync_team_from_github(db, "acme", "acme/widgets")

    assert result.candidate_count == 2
    team = await TeamRepository(db).get_raw_by_github_team("gh-1", 4711)
    assert team["_id"] == result.team_id
    assert team["name"] == "GitHub Team: acme/payments"
    assert team["members"] == [{"user_id": "u-1", "role": "admin", "source": "github"}]
