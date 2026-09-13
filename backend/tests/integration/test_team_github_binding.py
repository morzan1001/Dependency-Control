"""Which teams a GitHub group may bind itself to, and which ones are somebody else's already."""

import pytest

from app.models.team import Team
from app.repositories.teams import TeamRepository
from tests.mocks.fake_mongo import FakeDatabase

_BINDING = {
    "github_instance_id": "gh-1",
    "github_org": "acme",
    "github_team_id": 9000,
    "github_team_slug": "orion",
}


async def _seeded(db) -> TeamRepository:
    repo = TeamRepository(db)
    await repo.create(Team(id="t-free", name="Orion"))
    await repo.create(
        Team(id="t-github", name="Payments", github_instance_id="gh-2", github_org="other", github_team_id=1234)
    )
    await repo.create(Team(id="t-gitlab", name="Cards", gitlab_instance_id="gl-1", gitlab_group_id=77))
    return repo


async def _assert_only_the_unclaimed_team_is_offered(db) -> None:
    repo = await _seeded(db)

    unbound = await repo.find_raw_unbound()

    assert [team["_id"] for team in unbound] == ["t-free"]
    # The name is all the matching needs, and every team of the installation is read.
    assert set(unbound[0]) == {"_id", "name"}


async def _assert_a_team_bound_in_the_meantime_is_not_rebound(db) -> None:
    """The read that picked the candidate and the write that binds it are two round trips."""
    repo = await _seeded(db)

    assert await repo.bind_github_team("t-github", _BINDING) is None

    kept = await repo.get_raw_by_id("t-github")
    assert (kept["github_instance_id"], kept["github_team_id"]) == ("gh-2", 1234)


async def _assert_an_unbound_team_takes_the_whole_binding(db) -> None:
    repo = await _seeded(db)

    bound = await repo.bind_github_team("t-free", _BINDING)

    assert bound is not None
    assert {key: bound[key] for key in _BINDING} == _BINDING
    assert bound["name"] == "Orion"
    stored = await repo.get_raw_by_github_team("gh-1", 9000)
    assert stored["_id"] == "t-free"


@pytest.mark.asyncio
async def test_only_the_team_no_provider_claims_is_offered_for_adoption():
    await _assert_only_the_unclaimed_team_is_offered(FakeDatabase())


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_only_the_team_no_provider_claims_is_offered_for_adoption_on_real_mongo(db):
    await _assert_only_the_unclaimed_team_is_offered(db)


@pytest.mark.asyncio
async def test_a_team_bound_in_the_meantime_is_not_bound_again():
    await _assert_a_team_bound_in_the_meantime_is_not_rebound(FakeDatabase())


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_a_team_bound_in_the_meantime_is_not_bound_again_on_real_mongo(db):
    await _assert_a_team_bound_in_the_meantime_is_not_rebound(db)


@pytest.mark.asyncio
async def test_an_unbound_team_takes_the_whole_binding():
    await _assert_an_unbound_team_takes_the_whole_binding(FakeDatabase())


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_an_unbound_team_takes_the_whole_binding_on_real_mongo(db):
    await _assert_an_unbound_team_takes_the_whole_binding(db)
