"""Live-only: the fake ignores collations, so case-insensitive name order needs the real server."""

import pytest

from app.api.v1.helpers.sorting import case_insensitive_key, case_insensitive_sort
from app.core.permissions import Permissions
from app.models.project import Project, ProjectMember
from app.models.team import Team
from app.models.user import User
from app.models.waiver import Waiver
from app.services.chat.tools import ChatToolRegistry

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


async def test_the_global_waivers_order_creators_whatever_their_case(client, db, admin_auth_headers):
    await db.users.insert_many(
        [
            User(id="u-1", username="Bob Example", email="bob@corp.com").model_dump(by_alias=True),
            User(id="u-2", username="alice.jensen", email="alice@corp.com").model_dump(by_alias=True),
        ]
    )
    # "Dave" and "carol" name no account, as a creator stored before waivers kept ids.
    await db.waivers.insert_many(
        [Waiver(reason="accepted", created_by=by).model_dump(by_alias=True) for by in ("u-1", "Dave", "u-2", "carol")]
    )

    resp = await client.get(
        "/api/v1/waivers/",
        params={"global_only": True, "sort_by": "created_by", "sort_order": "asc"},
        headers=admin_auth_headers,
    )

    assert [waiver["created_by"] for waiver in resp.json()["items"]] == ["alice.jensen", "Bob Example", "carol", "Dave"]


@pytest.mark.parametrize("sort_by", ["finding_id", "package_name", "reason"])
async def test_the_waivers_order_finding_ids_packages_and_reasons_whatever_their_case(
    client, db, admin_auth_headers, sort_by
):
    await db.waivers.insert_many(
        [
            Waiver(**{"reason": "accepted", "created_by": "u-1", sort_by: value}).model_dump(by_alias=True)
            for value in ("Bob", "carol", "alice")
        ]
    )

    resp = await client.get(
        "/api/v1/waivers/",
        params={"global_only": True, "sort_by": sort_by, "sort_order": "asc"},
        headers=admin_auth_headers,
    )

    assert [waiver[sort_by] for waiver in resp.json()["items"]] == ["alice", "Bob", "carol"]


@pytest.mark.parametrize("sort_by", ["created_at", "created_by"])
@pytest.mark.parametrize(
    ("field", "values"),
    [("finding_id", ("CVE-2024-1", "cve-2024-1", "CVE-2024-2")), ("package_name", ("Django", "django", "Flask"))],
)
async def test_the_waiver_filters_match_case_exactly_as_waivers_apply(
    client, db, admin_auth_headers, sort_by, field, values
):
    await db.waivers.insert_many(
        [
            Waiver(**{"reason": "accepted", "created_by": "u-1", field: value}).model_dump(by_alias=True)
            for value in values
        ]
    )

    resp = await client.get(
        "/api/v1/waivers/",
        params={"global_only": True, field: values[0], "sort_by": sort_by},
        headers=admin_auth_headers,
    )

    assert resp.json()["total"] == 1
    assert [waiver[field] for waiver in resp.json()["items"]] == [values[0]]


async def test_the_chat_team_list_orders_names_whatever_their_case(db):
    await db.teams.insert_many(
        [Team(name=name).model_dump(by_alias=True) for name in ("Platform Engineering", "api-gateway", "Core")]
    )
    caller = User(id="u-1", username="u-1", email="u-1@corp.com", permissions=[Permissions.TEAM_READ_ALL])

    result = await ChatToolRegistry().execute_tool("list_teams", {}, caller, db)

    assert [team["name"] for team in result["teams"]] == ["api-gateway", "Core", "Platform Engineering"]


async def test_the_server_sorts_text_as_case_insensitive_key_does(db):
    names = ["Zahlung", "strat", "éclair", "Straße", "Ärzte", "navy", "Bravo", "naïve", "ezra", "cello", "eclair"]
    names += ["e\u0301clat", "Øresund", "oslo", "ŁÓDŹ", "lodz", "ȘTEFAN", "stefan", "Æsir", "aesir", "ABC", "abc", "_x"]
    await db.dependencies.insert_many([{"name": name} for name in names])

    for direction in (1, -1):
        rows = await db.dependencies.aggregate(case_insensitive_sort([("name", direction)], {"name"})).to_list(None)

        assert [row["name"] for row in rows] == sorted(names, key=case_insensitive_key, reverse=direction < 0)
