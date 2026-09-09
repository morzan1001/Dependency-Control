"""Callgraph access and project access must not be able to disagree."""

import pytest

from app.api.v1.helpers.callgraph import _effective_project_role
from app.api.v1.helpers.projects import team_derived_role
from app.repositories.teams import TeamRepository
from tests.mocks.fake_mongo import FakeDatabase

_USER = "u1"


@pytest.mark.asyncio
async def test_the_callgraph_role_matches_the_shared_resolver():
    """One resolver decides who may write; the callgraph gate must not answer differently."""
    db = FakeDatabase()
    await db.teams.insert_one({"_id": "t1", "name": "t1", "members": [{"user_id": _USER, "role": "member"}]})
    team_repo = TeamRepository(db)
    project = {"_id": "p1", "members": [], "team_id": "t1"}

    assert await _effective_project_role(project, _USER, team_repo) == "viewer"
    assert await team_derived_role(["t1"], _USER, team_repo) == "viewer"


@pytest.mark.asyncio
async def test_a_stronger_team_role_lifts_a_weaker_direct_member():
    """The team half of the composition has to be consulted, not just the direct half."""
    db = FakeDatabase()
    await db.teams.insert_one({"_id": "t1", "name": "t1", "members": [{"user_id": _USER, "role": "admin"}]})
    project = {"_id": "p1", "members": [{"user_id": _USER, "role": "viewer"}], "team_id": "t1"}

    assert await _effective_project_role(project, _USER, TeamRepository(db)) == "admin"


@pytest.mark.asyncio
async def test_a_stronger_direct_role_is_not_lowered_by_a_weaker_team_role():
    """Adding a team must never downgrade someone who already had more."""
    db = FakeDatabase()
    await db.teams.insert_one({"_id": "t1", "name": "t1", "members": [{"user_id": _USER, "role": "member"}]})
    project = {"_id": "p1", "members": [{"user_id": _USER, "role": "admin"}], "team_id": "t1"}

    assert await _effective_project_role(project, _USER, TeamRepository(db)) == "admin"


@pytest.mark.asyncio
async def test_the_resolver_ignores_a_stale_stored_team_array_and_reads_the_scalar():
    """The resolver reads the scalar team_id only; the stored team_ids array is never consulted."""
    db = FakeDatabase()
    await db.teams.insert_one({"_id": "old", "name": "old", "members": [{"user_id": _USER, "role": "admin"}]})
    await db.teams.insert_one({"_id": "new", "name": "new", "members": [{"user_id": _USER, "role": "member"}]})
    team_repo = TeamRepository(db)
    project = {"_id": "p1", "members": [], "team_id": "new", "team_ids": ["old"]}

    assert await _effective_project_role(project, _USER, team_repo) == "viewer"
