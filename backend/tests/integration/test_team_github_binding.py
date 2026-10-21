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
    """With the condition in the filter, a binding written after the conflict check is replaced, not doubled."""
    repo = await _seeded(db)

    await repo.replace_binding_for_instance("t-this-instance", _BINDING)

    kept = await repo.get_raw_by_id("t-this-instance")
    assert [binding["key"] for binding in kept["bindings"]] == ["github:gh-1:9000"]


async def _assert_an_unbound_team_takes_the_whole_binding(db) -> None:
    repo = await _seeded(db)

    await repo.replace_binding_for_instance("t-free", _BINDING)

    bound = await repo.get_raw_by_id("t-free")
    assert bound["bindings"] == [_BINDING]
    assert bound["name"] == "Orion"
    stored = await repo.get_raw_by_binding_key("github:gh-1:9000")
    assert stored["_id"] == "t-free"


async def _assert_a_team_of_another_instance_gains_a_second_binding(db) -> None:
    """The whole point of a binding per instance: one team can answer for several."""
    repo = await _seeded(db)

    await repo.replace_binding_for_instance("t-other-instance", _BINDING)

    bound = await repo.get_raw_by_id("t-other-instance")
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
