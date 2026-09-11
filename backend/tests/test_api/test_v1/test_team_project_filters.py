"""Filtering projects by team, wherever that question is asked.

"Which projects does this team own" is the ownership relation itself, so a project two teams own
answers to both. Each of these filters is either combined with the visibility query or reached
behind a team-membership check, so the risk here is the opposite one: a co-owned project must
appear under every owner, and a project the team does not own under none.
"""

import pytest

from app.api.v1.endpoints.projects import read_projects
from app.core.permissions import Permissions
from app.models.user import User
from app.services.chat.tools.registry import ChatToolRegistry
from tests.mocks.fake_mongo import FakeDatabase

_USER = "u1"

_PROJECTS = [
    {"_id": "co-owned", "name": "co-owned", "team_ids": ["alpha", "bravo"], "team_id": "alpha", "members": []},
    {"_id": "alpha-only", "name": "alpha-only", "team_ids": ["alpha"], "team_id": "alpha", "members": []},
    {"_id": "bravo-only", "name": "bravo-only", "team_ids": ["bravo"], "team_id": "bravo", "members": []},
    {"_id": "unowned", "name": "unowned", "team_ids": [], "team_id": None, "members": []},
]


async def _seed() -> FakeDatabase:
    db = FakeDatabase()
    for project in _PROJECTS:
        await db.projects.insert_one(dict(project))
    for team_id in ("alpha", "bravo"):
        await db.teams.insert_one(
            {"_id": team_id, "name": team_id, "members": [{"user_id": _USER, "role": "member"}]}
        )
    return db


def _user() -> User:
    return User(id=_USER, username=_USER, email="u1@test.com", permissions=[Permissions.PROJECT_READ])


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("team_id", "expected"),
    [("alpha", {"co-owned", "alpha-only"}), ("bravo", {"co-owned", "bravo-only"})],
)
async def test_the_project_list_filter_holds_every_project_a_team_co_owns(team_id, expected):
    page = await read_projects(_user(), await _seed(), team_id=team_id)

    assert {project.id for project in page["items"]} == expected


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("team_id", "expected"),
    [("alpha", {"co-owned", "alpha-only"}), ("bravo", {"co-owned", "bravo-only"})],
)
async def test_the_chat_team_projects_tool_holds_every_project_a_team_co_owns(team_id, expected):
    result = await ChatToolRegistry()._dispatch("get_team_projects", {"team_id": team_id}, _user(), await _seed())

    assert {project["id"] for project in result["projects"]} == expected


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("team_id", "expected"),
    [("alpha", {"co-owned", "alpha-only"}), ("bravo", {"co-owned", "bravo-only"})],
)
async def test_the_chat_team_risk_tool_holds_every_project_a_team_co_owns(team_id, expected):
    result = await ChatToolRegistry()._dispatch("get_team_risk_overview", {"team_id": team_id}, _user(), await _seed())

    assert result["project_count"] == len(expected)
