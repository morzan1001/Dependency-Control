"""Which projects a user may see, from the one query that answers it.

The team half is an ownership test now: a project answers to every team that owns it, and to no
other. Both halves are asserted against a database rather than against the query document, so a
filter that reads correctly but selects the wrong documents still fails.
"""

import pytest

from app.api.v1.helpers.projects import build_user_project_query
from app.core.permissions import Permissions
from app.models.user import User
from app.repositories.teams import TeamRepository
from app.services.analytics.scopes import ScopeResolver
from tests.mocks.fake_mongo import FakeDatabase

_USER = "u1"

# The scalar names one owner and the list names both, which is the shape every project has while
# the mirror is still written: a reader of the scalar under-shows, a reader of the list does not.
_PROJECTS = [
    {"_id": "co-owned", "name": "co-owned", "team_ids": ["a", "b"], "team_id": "a", "members": []},
    {"_id": "mine-only", "name": "mine-only", "team_ids": ["b"], "team_id": "b", "members": []},
    {"_id": "theirs", "name": "theirs", "team_ids": ["c"], "team_id": "c", "members": []},
    {"_id": "unassigned", "name": "unassigned", "team_ids": [], "team_id": None, "members": []},
    {"_id": "never-written", "name": "never-written", "members": []},
    {"_id": "direct", "name": "direct", "team_ids": ["c"], "team_id": "c", "members": [{"user_id": _USER}]},
]


async def _seeded_db() -> FakeDatabase:
    db = FakeDatabase()
    for project in _PROJECTS:
        await db.projects.insert_one(dict(project))
    await db.teams.insert_one({"_id": "b", "name": "b", "members": [{"user_id": _USER, "role": "member"}]})
    await db.teams.insert_one({"_id": "a", "name": "a", "members": [{"user_id": "someone-else", "role": "admin"}]})
    await db.teams.insert_one({"_id": "c", "name": "c", "members": [{"user_id": "someone-else", "role": "admin"}]})
    return db


def _user(*permissions) -> User:
    return User(id=_USER, username=_USER, email="u1@test.com", permissions=list(permissions))


async def _visible(db, user: User) -> set[str]:
    query = await build_user_project_query(user, TeamRepository(db))
    return {doc["_id"] for doc in await db.projects.find(query).to_list(None)}


@pytest.mark.asyncio
async def test_a_co_owned_project_answers_to_every_owner():
    db = await _seeded_db()

    assert await _visible(db, _user(Permissions.PROJECT_READ)) == {"co-owned", "mine-only", "direct"}


@pytest.mark.asyncio
async def test_a_project_none_of_my_teams_own_stays_invisible():
    """The widening half: an ownership filter that matched more than the owners would show these."""
    db = await _seeded_db()

    visible = await _visible(db, _user(Permissions.PROJECT_READ))

    assert "theirs" not in visible
    assert "unassigned" not in visible
    assert "never-written" not in visible


@pytest.mark.asyncio
async def test_a_user_in_no_team_sees_only_what_they_are_a_member_of():
    """An empty team list must select nothing, not everything."""
    db = await _seeded_db()
    await db.teams.delete_many({})

    assert await _visible(db, _user(Permissions.PROJECT_READ)) == {"direct"}


@pytest.mark.asyncio
async def test_read_all_is_unfiltered():
    db = await _seeded_db()

    assert await build_user_project_query(_user(Permissions.PROJECT_READ_ALL), TeamRepository(db)) == {}


@pytest.mark.asyncio
async def test_the_analytics_scope_answers_the_same_projects():
    """Two spellings of one access rule drift; the user scope has to be the same set, not a copy."""
    db = await _seeded_db()
    user = _user(Permissions.PROJECT_READ)

    resolved = await ScopeResolver(db, user).resolve(scope="user", scope_id=None)

    assert set(resolved.project_ids or []) == await _visible(db, user)


@pytest.mark.asyncio
async def test_the_analytics_scope_is_unfiltered_for_read_all():
    db = await _seeded_db()

    resolved = await ScopeResolver(db, _user(Permissions.PROJECT_READ_ALL)).resolve(scope="user", scope_id=None)

    assert set(resolved.project_ids or []) == {project["_id"] for project in _PROJECTS}


@pytest.mark.asyncio
async def test_a_team_scope_holds_every_project_the_team_co_owns():
    db = await _seeded_db()

    resolved = await ScopeResolver(db, _user(Permissions.PROJECT_READ)).resolve(scope="team", scope_id="b")

    assert set(resolved.project_ids or []) == {"co-owned", "mine-only"}
