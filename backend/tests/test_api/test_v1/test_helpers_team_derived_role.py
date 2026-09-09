"""One resolver derives a project role from every team that owns the project."""

import pytest

from app.api.v1.helpers.projects import team_derived_role
from app.repositories.teams import TeamRepository
from tests.mocks.fake_mongo import FakeDatabase

_USER = "u1"
_OTHER = "u2"


async def _repo(*teams):
    db = FakeDatabase()
    for team in teams:
        await db.teams.insert_one(team)
    return TeamRepository(db)


def _team(team_id, members):
    return {"_id": team_id, "name": team_id, "members": members}


@pytest.mark.asyncio
async def test_no_teams_grants_nothing():
    assert await team_derived_role([], _USER, await _repo()) is None


@pytest.mark.asyncio
async def test_a_team_member_gets_viewer():
    repo = await _repo(_team("t1", [{"user_id": _USER, "role": "member"}]))

    assert await team_derived_role(["t1"], _USER, repo) == "viewer"


@pytest.mark.asyncio
async def test_a_team_admin_gets_project_admin():
    repo = await _repo(_team("t1", [{"user_id": _USER, "role": "admin"}]))

    assert await team_derived_role(["t1"], _USER, repo) == "admin"


@pytest.mark.asyncio
async def test_a_non_member_of_the_only_team_gets_nothing():
    repo = await _repo(_team("t1", [{"user_id": _OTHER, "role": "admin"}]))

    assert await team_derived_role(["t1"], _USER, repo) is None


@pytest.mark.asyncio
async def test_the_strongest_role_across_several_teams_wins():
    """Adding a co-owner team must never downgrade an incumbent."""
    repo = await _repo(
        _team("t1", [{"user_id": _USER, "role": "member"}]),
        _team("t2", [{"user_id": _USER, "role": "admin"}]),
    )

    assert await team_derived_role(["t1", "t2"], _USER, repo) == "admin"


@pytest.mark.asyncio
async def test_the_result_does_not_depend_on_team_order():
    """Array order is set by whichever writer touched the field last, so it must not decide access."""
    teams = (
        _team("t1", [{"user_id": _USER, "role": "member"}]),
        _team("t2", [{"user_id": _USER, "role": "admin"}]),
    )

    assert await team_derived_role(["t1", "t2"], _USER, await _repo(*teams)) == "admin"
    assert await team_derived_role(["t2", "t1"], _USER, await _repo(*teams)) == "admin"


@pytest.mark.asyncio
async def test_membership_in_one_of_several_teams_is_enough():
    repo = await _repo(
        _team("t1", [{"user_id": _OTHER, "role": "admin"}]),
        _team("t2", [{"user_id": _USER, "role": "member"}]),
    )

    assert await team_derived_role(["t1", "t2"], _USER, repo) == "viewer"


@pytest.mark.asyncio
async def test_a_team_id_pointing_at_nothing_is_skipped():
    """A dangling id must not deny access the surviving teams grant."""
    repo = await _repo(_team("t2", [{"user_id": _USER, "role": "admin"}]))

    assert await team_derived_role(["gone", "t2"], _USER, repo) == "admin"
