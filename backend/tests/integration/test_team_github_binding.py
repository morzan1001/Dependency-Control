"""What a binding written by hand does to the team that already holds one on the instance."""

import pytest

from app.models.team import GitHubTeamBinding, GitLabGroupBinding, Team
from app.repositories.teams import TeamRepository
from tests.mocks.fake_mongo import FakeDatabase

_BINDING = GitHubTeamBinding(instance_id="gh-1", org="acme", external_id=9000, slug="orion").model_dump()


async def _seeded(db) -> TeamRepository:
    repo = TeamRepository(db)
    await repo.create(Team(id="t-free", name="Orion"))
    await repo.create(
        Team(
            id="t-this-instance",
            name="Payments",
            bindings=[GitHubTeamBinding(instance_id="gh-1", org="other", external_id=1234)],
        )
    )
    await repo.create(
        Team(
            id="t-other-instance",
            name="Cards",
            bindings=[GitHubTeamBinding(instance_id="gh-2", org="other", external_id=1234)],
        )
    )
    await repo.create(
        Team(id="t-gitlab", name="Edge", bindings=[GitLabGroupBinding(instance_id="gl-1", external_id=77)])
    )
    return repo


async def _assert_a_team_bound_in_the_meantime_is_not_rebound(db) -> None:
    """The condition sits in the filter, so a binding written between the endpoint's conflict check
    and this write is replaced in place rather than doubled."""
    repo = await _seeded(db)

    assert await repo.add_binding_if_absent("t-this-instance", _BINDING) is None

    kept = await repo.get_raw_by_id("t-this-instance")
    assert [binding["key"] for binding in kept["bindings"]] == ["github:gh-1:1234"]


async def _assert_an_unbound_team_takes_the_whole_binding(db) -> None:
    repo = await _seeded(db)

    bound = await repo.add_binding_if_absent("t-free", _BINDING)

    assert bound is not None
    assert bound["bindings"] == [_BINDING]
    assert bound["name"] == "Orion"
    stored = await repo.get_raw_by_binding_key("github:gh-1:9000")
    assert stored["_id"] == "t-free"


async def _assert_a_team_of_another_instance_gains_a_second_binding(db) -> None:
    """The whole point of a binding per instance: one team can answer for several."""
    repo = await _seeded(db)

    bound = await repo.add_binding_if_absent("t-other-instance", _BINDING)

    assert bound is not None
    assert sorted(binding["key"] for binding in bound["bindings"]) == ["github:gh-1:9000", "github:gh-2:1234"]


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


@pytest.mark.asyncio
async def test_a_team_bound_to_another_instance_gains_a_second_binding():
    await _assert_a_team_of_another_instance_gains_a_second_binding(FakeDatabase())


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_a_team_bound_to_another_instance_gains_a_second_binding_on_real_mongo(db):
    await _assert_a_team_of_another_instance_gains_a_second_binding(db)
