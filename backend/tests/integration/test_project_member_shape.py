"""Stored members hold only what a member is; the username and the team-derived role are filled in on read."""

import pytest

from tests.helpers.auth import bearer_headers
from tests.helpers.permission_presets import PRESET_USER

pytestmark = pytest.mark.asyncio

_STORED_KEYS = {"user_id", "role", "notification_preferences"}
_VIEW_KEYS = {"username", "inherited_from", "effective_role"}


async def test_a_created_project_stores_its_creator_without_read_side_fields(client, db, member_auth_headers):
    resp = await client.post("/api/v1/projects/", json={"name": "fresh"}, headers=member_auth_headers)
    assert resp.status_code == 201, resp.text

    stored = await db.projects.find_one({"_id": resp.json()["project_id"]})
    assert [set(member) for member in stored["members"]] == [_STORED_KEYS]


async def test_an_invited_user_is_stored_without_read_side_fields(client, db, owner_auth_headers_proj):
    await db.users.insert_one(
        {"_id": "invitee", "username": "invitee", "email": "invitee@corp.com", "is_verified": True}
    )

    resp = await client.post(
        "/api/v1/projects/p/invite", json={"email": "invitee@corp.com"}, headers=owner_auth_headers_proj
    )
    assert resp.status_code == 200, resp.text

    stored = await db.projects.find_one({"_id": "p"})
    assert [set(member) for member in stored["members"] if member["user_id"] == "invitee"] == [_STORED_KEYS]


async def test_a_project_answer_still_carries_the_read_side_member_fields(client, db, owner_auth_headers_proj):
    await db.users.insert_one({"_id": "ownerp", "username": "Owner P", "email": "ownerp@corp.com"})
    await db.teams.insert_one({"_id": "t1", "name": "Team One", "members": [{"user_id": "teammate", "role": "member"}]})
    await db.projects.update_one({"_id": "p"}, {"$set": {"team_ids": ["t1"]}})

    detail = (await client.get("/api/v1/projects/p", headers=owner_auth_headers_proj)).json()
    updated = await client.put(
        "/api/v1/projects/p/members/ownerp", json={"role": "admin"}, headers=owner_auth_headers_proj
    )
    listing = await client.get("/api/v1/projects/", headers=bearer_headers("ownerp", PRESET_USER))

    assert {m["user_id"]: (m["username"], m["effective_role"], m["inherited_from"]) for m in detail["members"]} == {
        "ownerp": ("Owner P", "admin", None),
        "teammate": (None, "viewer", "Team: Team One"),
    }
    assert updated.status_code == 200, updated.text
    assert [set(m) for m in updated.json()["members"]] == [_STORED_KEYS | _VIEW_KEYS]
    [listed] = [project for project in listing.json()["items"] if project["id"] == "p"]
    assert [set(m) for m in listed["members"]] == [_STORED_KEYS | _VIEW_KEYS]
