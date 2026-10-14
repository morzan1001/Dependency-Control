"""The users and teams lists order names alphabetically whatever their case; the fake ignores collations."""

import pytest

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
