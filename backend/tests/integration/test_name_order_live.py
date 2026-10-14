"""The users, teams and projects lists order names alphabetically whatever their case; the fake ignores collations."""

import pytest

from app.models.project import Project, ProjectMember
from app.models.team import Team
from app.models.user import User

pytestmark = [pytest.mark.asyncio, pytest.mark.live_mongo]


@pytest.mark.parametrize(
    ("sort_order", "expected"),
    [("asc", ["alice.jensen", "Bob Example", "carol"]), ("desc", ["carol", "Bob Example", "alice.jensen"])],
)
async def test_the_users_list_orders_usernames_whatever_their_case(
    client, db, admin_auth_headers, sort_order, expected
):
    await db.users.insert_many(
        [
            User(username=name, email=f"{name.split()[0].lower()}@corp.com").model_dump(by_alias=True)
            for name in ("Bob Example", "carol", "alice.jensen")
        ]
    )

    resp = await client.get(
        "/api/v1/users/", params={"sort_by": "username", "sort_order": sort_order}, headers=admin_auth_headers
    )

    assert [user["username"] for user in resp.json()] == expected


async def test_the_teams_list_orders_names_whatever_their_case(client, db, admin_auth_headers):
    await db.teams.insert_many(
        [Team(name=name).model_dump(by_alias=True) for name in ("Platform Engineering", "api-gateway", "Core")]
    )

    resp = await client.get(
        "/api/v1/teams/", params={"sort_by": "name", "sort_order": "asc"}, headers=admin_auth_headers
    )

    assert [team["name"] for team in resp.json()] == ["api-gateway", "Core", "Platform Engineering"]


async def test_the_projects_list_orders_a_members_projects_whatever_their_case(client, db, member_auth_headers):
    # member_auth_headers makes "testuser" a member of the fixture's "test-project".
    membership = [ProjectMember(user_id="testuser", role="viewer")]
    await db.projects.insert_many(
        [
            Project(name="Zeta Service", members=membership).model_dump(by_alias=True),
            Project(name="alpha-api", members=membership).model_dump(by_alias=True),
            Project(name="Beta Internal").model_dump(by_alias=True),
        ]
    )

    resp = await client.get(
        "/api/v1/projects/", params={"sort_by": "name", "sort_order": "asc"}, headers=member_auth_headers
    )

    assert [project["name"] for project in resp.json()["items"]] == ["alpha-api", "test-project", "Zeta Service"]
