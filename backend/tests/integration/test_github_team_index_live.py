"""The GitHub team index must not make a second manual team unwritable."""

import pytest

from app.core.init_db import create_indexes
from app.models.team import Team
from app.repositories.teams import TeamRepository


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_two_manual_teams_coexist_under_the_github_team_index(db):
    await create_indexes(db)
    repo = TeamRepository(db)

    await repo.create(Team(name="Atlas"))
    await repo.create(Team(name="Borealis"))

    assert await repo.count({}) == 2


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_the_same_github_team_cannot_be_created_twice(db):
    from pymongo.errors import DuplicateKeyError

    await create_indexes(db)
    repo = TeamRepository(db)
    fields = {"github_instance_id": "gh-1", "github_org": "acme", "github_team_id": 4711}

    await repo.create(Team(name="GitHub Team: acme/payments", **fields))
    with pytest.raises(DuplicateKeyError):
        await repo.create(Team(name="GitHub Team: acme/payments", **fields))
