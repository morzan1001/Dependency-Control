"""Over HTTP, a stored person reference is the account id and the response names the account as it is named now."""

import pytest

# The client fixture authenticates "admin-user" under that id; the account has since been renamed.
_ADMIN = {"_id": "admin-user", "username": "root", "email": "root@corp.com", "permissions": []}


@pytest.mark.asyncio
async def test_a_waiver_answers_with_its_creators_current_name(client, db, admin_auth_headers):
    await db.users.insert_one(dict(_ADMIN))

    created = await client.post(
        "/api/v1/waivers/", json={"package_name": "requests", "reason": "vendored"}, headers=admin_auth_headers
    )
    waiver_id = created.json()["id"]
    read = await client.get(f"/api/v1/waivers/{waiver_id}", headers=admin_auth_headers)
    listed = await client.get("/api/v1/waivers/", params={"global_only": True}, headers=admin_auth_headers)

    assert (created.status_code, read.status_code, listed.status_code) == (201, 200, 200)
    assert [created.json()["created_by"], read.json()["created_by"]] == ["root", "root"]
    assert [item["created_by"] for item in listed.json()["items"]] == ["root"]
    assert (await db.waivers.find_one({"_id": waiver_id}))["created_by"] == "admin-user"
