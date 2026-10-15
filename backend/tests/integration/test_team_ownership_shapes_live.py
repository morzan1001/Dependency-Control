"""Whether a co-owned project counts once or per owner is the engine's answer, so each case also runs live."""

import pytest

from app.api.v1.endpoints.projects import get_dashboard_stats, read_projects
from app.core.permissions import Permissions
from app.models.user import User
from tests.mocks.fake_mongo import FakeDatabase

_ALPHA = "alpha"
_BRAVO = "bravo"

# One of every shape ownership is stored in.
_PROJECTS = [
    {"_id": "solo", "name": "solo", "team_ids": [_ALPHA], "members": [], "stats": {"critical": 1, "high": 0}},
    {"_id": "co", "name": "co", "team_ids": [_ALPHA, _BRAVO], "members": [], "stats": {"critical": 10, "high": 0}},
    {"_id": "other", "name": "other", "team_ids": [_BRAVO], "members": [], "stats": {"critical": 100, "high": 0}},
    {"_id": "empty", "name": "empty", "team_ids": [], "members": [], "stats": {"critical": 1000, "high": 0}},
]

_UNOWNED = {"empty"}


async def _seed(db):
    for project in _PROJECTS:
        await db.projects.insert_one(dict(project))
    for team_id in (_ALPHA, _BRAVO):
        await db.teams.insert_one({"_id": team_id, "name": team_id, "members": []})


def _reader_of_everything() -> User:
    return User(
        id="u-all",
        username="u-all",
        email="u-all@test.com",
        permissions=[Permissions.PROJECT_READ_ALL],
    )


async def _assert_the_estate_total_counts_a_co_owned_project_once(db) -> None:
    await _seed(db)

    stats = await get_dashboard_stats(db, _reader_of_everything())

    assert stats["total_projects"] == len(_PROJECTS)
    assert stats["total_critical"] == sum(p["stats"]["critical"] for p in _PROJECTS)


async def _assert_a_project_counts_in_full_under_every_team_that_owns_it(db) -> None:
    await _seed(db)
    user = _reader_of_everything()

    per_team = {team_id: await read_projects(user, db, team_id=team_id, limit=100) for team_id in (_ALPHA, _BRAVO)}
    owned = len(_PROJECTS) - len(_UNOWNED)

    assert {team: {p.id for p in page["items"]} for team, page in per_team.items()} == {
        _ALPHA: {"solo", "co"},
        _BRAVO: {"co", "other"},
    }
    # A co-owned project is whole to each owner, so per-team totals deliberately outrun the owned count.
    assert sum(page["total"] for page in per_team.values()) == owned + 1


@pytest.mark.asyncio
async def test_the_estate_total_counts_a_co_owned_project_once():
    await _assert_the_estate_total_counts_a_co_owned_project_once(FakeDatabase())


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_the_estate_total_counts_a_co_owned_project_once_on_real_mongo(db):
    await _assert_the_estate_total_counts_a_co_owned_project_once(db)


@pytest.mark.asyncio
async def test_a_project_counts_in_full_under_every_team_that_owns_it():
    await _assert_a_project_counts_in_full_under_every_team_that_owns_it(FakeDatabase())


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_a_project_counts_in_full_under_every_team_that_owns_it_on_real_mongo(db):
    await _assert_a_project_counts_in_full_under_every_team_that_owns_it(db)
