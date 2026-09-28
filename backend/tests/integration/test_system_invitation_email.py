"""A system invitation takes a validated address and stores it lowercased, as every account email is."""

import pytest

_PATH = "/api/v1/invitations/system"


@pytest.mark.asyncio
async def test_the_invited_address_is_stored_lowercased(client, db, admin_auth_headers):
    resp = await client.post(_PATH, json={"email": "Invitee@Corp.com"}, headers=admin_auth_headers)

    assert resp.status_code == 201, resp.text
    assert (await db.system_invitations.find_one({}))["email"] == "invitee@corp.com"


@pytest.mark.asyncio
async def test_a_malformed_address_is_refused(client, db, admin_auth_headers):
    resp = await client.post(_PATH, json={"email": "not-an-address"}, headers=admin_auth_headers)

    assert resp.status_code == 422
    assert await db.system_invitations.find_one({}) is None
