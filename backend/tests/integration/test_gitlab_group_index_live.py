"""The GitLab group index must refuse a second holder without making manual teams unwritable."""

import pytest

from app.core.init_db import create_team_indexes
from app.models.team import Team
from app.repositories.teams import TeamRepository


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_two_manual_teams_coexist_under_the_gitlab_group_index(db):
    await create_team_indexes(db)
    repo = TeamRepository(db)

    await repo.create(Team(name="Atlas"))
    await repo.create(Team(name="Borealis"))

    assert await repo.count({}) == 2


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_the_same_gitlab_group_cannot_be_bound_twice(db):
    from pymongo.errors import DuplicateKeyError

    await create_team_indexes(db)
    repo = TeamRepository(db)
    fields = {"gitlab_instance_id": "gl-1", "gitlab_group_id": 77}

    await repo.create(Team(name="GitLab Group: mo/edge", **fields))
    with pytest.raises(DuplicateKeyError):
        await repo.create(Team(name="Edge Guild", **fields))


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_a_team_cleared_of_its_gitlab_binding_leaves_the_group_free(db):
    """Clearing nulls the pair, and the partial filter keeps a null pair out of the unique scope."""
    await create_team_indexes(db)
    repo = TeamRepository(db)

    await repo.create(Team(id="t-1", name="Edge Guild", gitlab_instance_id="gl-1", gitlab_group_id=77))
    await repo.update("t-1", {"gitlab_instance_id": None, "gitlab_group_id": None, "gitlab_group_path": None})
    await repo.create(Team(id="t-2", name="Edge Again", gitlab_instance_id="gl-1", gitlab_group_id=77))

    assert (await repo.get_raw_by_gitlab_group("gl-1", 77))["_id"] == "t-2"


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_one_team_holds_a_group_and_an_organisation_at_once(db):
    """The two provider indexes are independent, so a team can answer for both."""
    await create_team_indexes(db)
    repo = TeamRepository(db)

    await repo.create(
        Team(
            id="t-both",
            name="Edge Guild",
            gitlab_instance_id="gl-1",
            gitlab_group_id=77,
            github_instance_id="gh-1",
            github_org="acme",
            github_team_id=4711,
        )
    )

    assert (await repo.get_raw_by_gitlab_group("gl-1", 77))["_id"] == "t-both"
    assert (await repo.get_raw_by_github_team("gh-1", 4711))["_id"] == "t-both"
