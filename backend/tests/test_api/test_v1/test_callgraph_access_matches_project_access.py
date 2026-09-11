"""Callgraph access and project access must not be able to disagree."""

import pytest
from fastapi import HTTPException

from app.api.v1.helpers.callgraph import _effective_project_role, check_callgraph_access
from app.api.v1.helpers.projects import check_project_access
from app.core.constants import (
    PROJECT_ROLE_ADMIN,
    PROJECT_ROLE_EDITOR,
    PROJECT_ROLE_VIEWER,
    TEAM_ROLE_ADMIN,
    TEAM_ROLE_MEMBER,
)
from app.core.permissions import Permissions
from app.models.user import User
from app.repositories.teams import TeamRepository
from tests.mocks.fake_mongo import FakeDatabase

_USER = "u1"


@pytest.mark.asyncio
async def test_the_callgraph_role_matches_the_shared_resolver():
    """One resolver decides who may write; the callgraph gate must not answer differently."""
    db = FakeDatabase()
    await db.teams.insert_one({"_id": "t1", "name": "t1", "members": [{"user_id": _USER, "role": "member"}]})
    team_repo = TeamRepository(db)
    project = {"_id": "p1", "members": [], "team_ids": ["t1"]}

    assert await _effective_project_role(project, _USER, team_repo) == "viewer"


@pytest.mark.asyncio
async def test_a_stronger_team_role_lifts_a_weaker_direct_member():
    """The team half of the composition has to be consulted, not just the direct half."""
    db = FakeDatabase()
    await db.teams.insert_one({"_id": "t1", "name": "t1", "members": [{"user_id": _USER, "role": "admin"}]})
    project = {"_id": "p1", "members": [{"user_id": _USER, "role": "viewer"}], "team_ids": ["t1"]}

    assert await _effective_project_role(project, _USER, TeamRepository(db)) == "admin"


@pytest.mark.asyncio
async def test_a_stronger_direct_role_is_not_lowered_by_a_weaker_team_role():
    """Adding a team must never downgrade someone who already had more."""
    db = FakeDatabase()
    await db.teams.insert_one({"_id": "t1", "name": "t1", "members": [{"user_id": _USER, "role": "member"}]})
    project = {"_id": "p1", "members": [{"user_id": _USER, "role": "admin"}], "team_ids": ["t1"]}

    assert await _effective_project_role(project, _USER, TeamRepository(db)) == "admin"


@pytest.mark.asyncio
async def test_the_resolver_reads_the_stored_team_array_and_ignores_the_scalar():
    """The stored list is the ownership record; a scalar left behind by a writer decides nothing."""
    db = FakeDatabase()
    await db.teams.insert_one({"_id": "stored", "name": "stored", "members": [{"user_id": _USER, "role": "admin"}]})
    await db.teams.insert_one({"_id": "scalar", "name": "scalar", "members": [{"user_id": _USER, "role": "member"}]})
    team_repo = TeamRepository(db)
    project = {"_id": "p1", "members": [], "team_id": "scalar", "team_ids": ["stored"]}

    assert await _effective_project_role(project, _USER, team_repo) == "admin"


_GATE_USER = User(id=_USER, username=_USER, email="u1@test.com", permissions=[Permissions.PROJECT_READ])

# direct project role, team role, write request, allowed
_GATE_MATRIX = [
    (None, None, False, False),
    (None, None, True, False),
    (None, TEAM_ROLE_MEMBER, False, True),
    (None, TEAM_ROLE_MEMBER, True, False),
    (None, TEAM_ROLE_ADMIN, False, True),
    (None, TEAM_ROLE_ADMIN, True, True),
    (PROJECT_ROLE_VIEWER, None, False, True),
    (PROJECT_ROLE_VIEWER, None, True, False),
    (PROJECT_ROLE_VIEWER, TEAM_ROLE_MEMBER, False, True),
    (PROJECT_ROLE_VIEWER, TEAM_ROLE_MEMBER, True, False),
    (PROJECT_ROLE_VIEWER, TEAM_ROLE_ADMIN, False, True),
    (PROJECT_ROLE_VIEWER, TEAM_ROLE_ADMIN, True, True),
    (PROJECT_ROLE_ADMIN, None, False, True),
    (PROJECT_ROLE_ADMIN, None, True, True),
    (PROJECT_ROLE_ADMIN, TEAM_ROLE_MEMBER, False, True),
    (PROJECT_ROLE_ADMIN, TEAM_ROLE_MEMBER, True, True),
    (PROJECT_ROLE_ADMIN, TEAM_ROLE_ADMIN, False, True),
    (PROJECT_ROLE_ADMIN, TEAM_ROLE_ADMIN, True, True),
]


async def _seed_gate_db(direct_role: str | None, team_role: str | None) -> FakeDatabase:
    db = FakeDatabase()
    # The team always exists and always has a member, so a gate that keys off team existence
    # instead of the user's membership in it still fails the no-team-role rows.
    team_member = {"user_id": _USER if team_role else "someone-else", "role": team_role or TEAM_ROLE_ADMIN}
    await db.teams.insert_one({"_id": "t1", "name": "t1", "members": [team_member]})
    await db.projects.insert_one(
        {
            "_id": "p1",
            "name": "p1",
            "team_ids": ["t1"],
            "members": [{"user_id": _USER, "role": direct_role}] if direct_role else [],
        }
    )
    return db


async def _allows(gate_call) -> bool:
    try:
        await gate_call
    except HTTPException as exc:
        assert exc.status_code == 403
        return False
    return True


@pytest.mark.asyncio
@pytest.mark.parametrize(("direct_role", "team_role", "write", "allowed"), _GATE_MATRIX)
async def test_both_gates_reach_the_same_verdict(direct_role, team_role, write, allowed):
    """Both real gates, same input, same allow/deny — and that verdict is the expected one."""
    db = await _seed_gate_db(direct_role, team_role)
    # A callgraph write needs editor, so that is the project-gate request it corresponds to.
    required_role = PROJECT_ROLE_EDITOR if write else None

    project_allowed = await _allows(check_project_access("p1", _GATE_USER, db, required_role=required_role))
    callgraph_allowed = await _allows(check_callgraph_access("p1", _GATE_USER, db, require_write=write))

    assert project_allowed == callgraph_allowed
    assert project_allowed == allowed


# A project role is not on its own a licence to read projects: the resource gate wants both, and
# a surface that asks only for the role hands a member with no project permission the whole graph.
_UNREADING_USER = User(id=_USER, username=_USER, email="u1@test.com", permissions=[Permissions.ANALYTICS_READ])


@pytest.mark.asyncio
@pytest.mark.parametrize(("direct_role", "team_role", "write", "_allowed"), _GATE_MATRIX)
async def test_neither_gate_admits_a_member_holding_no_project_read(direct_role, team_role, write, _allowed):
    db = await _seed_gate_db(direct_role, team_role)
    required_role = PROJECT_ROLE_EDITOR if write else None

    assert not await _allows(check_project_access("p1", _UNREADING_USER, db, required_role=required_role))
    assert not await _allows(check_callgraph_access("p1", _UNREADING_USER, db, require_write=write))


@pytest.mark.asyncio
async def test_read_all_still_admits_a_reader_who_is_no_member():
    """The permission the members' check accepts in place of project:read is still accepted."""
    db = await _seed_gate_db(None, None)
    reader = User(id="outsider", username="outsider", email="o@test.com", permissions=[Permissions.PROJECT_READ_ALL])

    assert await _allows(check_project_access("p1", reader, db))
    assert await _allows(check_callgraph_access("p1", reader, db))


@pytest.mark.asyncio
async def test_read_all_stands_in_for_project_read_on_a_write():
    """read_all is no write permission, but it is a project-read one, and the members' check wants
    only that: an editor holding it and nothing else still writes. The write path is where the two
    are told apart, because a read request never reaches the check."""
    db = await _seed_gate_db(PROJECT_ROLE_EDITOR, None)
    editor = User(id=_USER, username=_USER, email="u1@test.com", permissions=[Permissions.PROJECT_READ_ALL])

    assert await _allows(check_project_access("p1", editor, db, required_role=PROJECT_ROLE_EDITOR))
    assert await _allows(check_callgraph_access("p1", editor, db, require_write=True))
