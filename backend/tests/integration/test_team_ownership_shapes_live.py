"""What a co-owned project does to a count, and what "no team" has to be spelled to catch.

Both questions are answered by the storage engine, not by our code: whether a document counts once
or once per owner depends on whether a pipeline unwound the array, and which documents a "no team"
filter reaches depends on how the server treats a missing field, an explicit null and an empty
array. Each assertion therefore runs against a real server as well as the double.
"""

import pytest

from app.api.v1.endpoints.projects import get_dashboard_stats, read_projects
from app.core.init_db import _normalise_unowned_projects
from app.core.permissions import Permissions
from app.models.user import User
from app.repositories.projects import UNSHAPED_OWNERS
from tests.mocks.fake_mongo import FakeDatabase

_ALPHA = "alpha"
_BRAVO = "bravo"

# One of every shape ownership is stored in, including the two a legacy document can carry.
_PROJECTS = [
    {"_id": "solo", "name": "solo", "team_ids": [_ALPHA], "members": [], "stats": {"critical": 1, "high": 0}},
    {"_id": "co", "name": "co", "team_ids": [_ALPHA, _BRAVO], "members": [], "stats": {"critical": 10, "high": 0}},
    {"_id": "other", "name": "other", "team_ids": [_BRAVO], "members": [], "stats": {"critical": 100, "high": 0}},
    {"_id": "empty", "name": "empty", "team_ids": [], "members": [], "stats": {"critical": 1000, "high": 0}},
    {"_id": "absent", "name": "absent", "members": [], "stats": {"critical": 10000, "high": 0}},
    {"_id": "null", "name": "null", "team_ids": None, "members": [], "stats": {"critical": 100000, "high": 0}},
]

_UNOWNED = {"empty", "absent", "null"}


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


async def _ids_matching(db, query) -> set[str]:
    return {doc["_id"] async for doc in db.projects.find(query, {"_id": 1})}


async def _assert_no_team_is_only_reached_once_every_shape_is_an_array(db) -> None:
    await _seed(db)

    # The spelling the plan reached for sees one of the three shapes, and the other two answer no
    # ownership filter either: without the normalisation below they are in no team view at all.
    assert await _ids_matching(db, {"team_ids": {"$size": 0}}) == {"empty"}
    assert await _ids_matching(db, UNSHAPED_OWNERS) == {"absent", "null"}

    await _normalise_unowned_projects(db)

    assert await _ids_matching(db, {"team_ids": {"$size": 0}}) == _UNOWNED
    assert await _ids_matching(db, UNSHAPED_OWNERS) == set()
    assert await _ids_matching(db, {"team_ids": {"$in": [_ALPHA, _BRAVO]}}) == {"solo", "co", "other"}

    # Idempotent: a second startup must not rewrite the documents the first one fixed.
    await _normalise_unowned_projects(db)
    assert await _ids_matching(db, {"team_ids": {"$size": 0}}) == _UNOWNED


async def _assert_the_estate_total_counts_a_co_owned_project_once(db) -> None:
    await _seed(db)
    await _normalise_unowned_projects(db)

    stats = await get_dashboard_stats(db, _reader_of_everything())

    assert stats["total_projects"] == len(_PROJECTS)
    assert stats["total_critical"] == sum(p["stats"]["critical"] for p in _PROJECTS)


async def _assert_a_project_counts_in_full_under_every_team_that_owns_it(db) -> None:
    await _seed(db)
    await _normalise_unowned_projects(db)
    user = _reader_of_everything()

    per_team = {team_id: await read_projects(user, db, team_id=team_id, limit=100) for team_id in (_ALPHA, _BRAVO)}
    owned = len(_PROJECTS) - len(_UNOWNED)

    assert {team: {p.id for p in page["items"]} for team, page in per_team.items()} == {
        _ALPHA: {"solo", "co"},
        _BRAVO: {"co", "other"},
    }
    # D2: the co-owned project is a whole project to each of its owners, so the per-team totals
    # overlap and deliberately outrun the number of projects that have an owner at all. A rollup
    # that made them add up would credit each owner with a fraction of a project nobody owns a
    # fraction of.
    assert sum(page["total"] for page in per_team.values()) == owned + 1


@pytest.mark.asyncio
async def test_no_team_is_only_reached_once_every_shape_is_an_array():
    await _assert_no_team_is_only_reached_once_every_shape_is_an_array(FakeDatabase())


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_no_team_is_only_reached_once_every_shape_is_an_array_on_real_mongo(db):
    await _assert_no_team_is_only_reached_once_every_shape_is_an_array(db)


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
