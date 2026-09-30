"""A system invitation takes a validated address, stores it lowercased and says whether its mail was queued."""

from unittest.mock import AsyncMock, patch

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


@pytest.mark.asyncio
async def test_without_a_mail_server_the_admin_is_told_to_share_the_link(client, db, admin_auth_headers):
    resp = await client.post(_PATH, json={"email": "invitee@corp.com"}, headers=admin_auth_headers)

    assert resp.status_code == 201, resp.text
    assert resp.json()["warning"] == "Email could not be sent. Share the link manually."


@pytest.mark.asyncio
async def test_a_queued_invitation_mail_carries_no_warning(client, db, admin_auth_headers):
    await db.system_settings.insert_one(
        {"_id": "current", "smtp_host": "smtp.example.com", "emails_from_email": "dc@example.com"}
    )
    with patch("app.api.v1.helpers.auth.EmailProvider") as provider:
        provider.return_value.send = AsyncMock()
        resp = await client.post(_PATH, json={"email": "invitee@corp.com"}, headers=admin_auth_headers)

    assert resp.status_code == 201, resp.text
    assert "warning" not in resp.json()
    assert provider.return_value.send.await_args.kwargs["destination"] == "invitee@corp.com"
