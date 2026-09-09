"""A GitHub-synced team is looked up by (instance, team id), never by id alone."""

import pytest

from app.models.team import Team
from app.repositories.teams import TeamRepository
from tests.mocks.fake_mongo import FakeDatabase


async def _seed(db) -> TeamRepository:
    repo = TeamRepository(db)
    await repo.create(
        Team(
            id="t-a",
            name="GitHub Team: acme/payments",
            github_instance_id="gh-1",
            github_org="acme",
            github_team_id=4711,
            github_team_slug="payments",
        )
    )
    await repo.create(
        Team(
            id="t-b",
            name="GitHub Team: other/billing",
            github_instance_id="gh-2",
            github_org="other",
            github_team_id=4711,
            github_team_slug="billing",
        )
    )
    return repo


async def _assert_scoped_to_the_instance(db) -> None:
    repo = await _seed(db)

    assert (await repo.get_raw_by_github_team("gh-1", 4711))["_id"] == "t-a"
    assert (await repo.get_raw_by_github_team("gh-2", 4711))["_id"] == "t-b"
    assert await repo.get_raw_by_github_team("gh-3", 4711) is None
    assert await repo.get_raw_by_github_team("gh-1", 9999) is None


@pytest.mark.asyncio
async def test_lookup_is_scoped_to_the_instance():
    await _assert_scoped_to_the_instance(FakeDatabase())


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_lookup_is_scoped_to_the_instance_on_real_mongo(db):
    await _assert_scoped_to_the_instance(db)
