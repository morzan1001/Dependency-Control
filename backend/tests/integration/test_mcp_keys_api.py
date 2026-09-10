"""CRUD for MCP API keys."""

import pytest
from jose import jwt

from app.core.config import settings
from app.core.permissions import Permissions
from app.repositories.mcp_api_keys import LIST_LIMIT, MCPApiKeyRepository

_BASE = "/api/v1/mcp-keys"

_OWNER = "mcp-owner"
_OTHER_OWNER = "another-owner"
_KEY_NAME = "claude-desktop"
_EXPIRY_DAYS = 30
_TOKEN_PREFIX = "mcp_"
_PREFIX_LENGTH = 12

_OK = 200
_CREATED = 201
_FORBIDDEN = 403
_NOT_FOUND = 404

_NO_KEYS = 0
_ONE_KEY = 1
_OVER_THE_PAGE = 3


def _headers(permissions, subject=_OWNER):
    token = jwt.encode(
        {"sub": subject, "permissions": list(permissions)},
        settings.SECRET_KEY,
        algorithm=settings.ALGORITHM,
    )
    return {"Authorization": f"Bearer {token}"}


async def _key_count(db):
    return await db["mcp_api_keys"].count_documents({})


@pytest.mark.asyncio
async def test_create_returns_plaintext_once_then_list_hides_it(client, db):
    headers = _headers([Permissions.MCP_ACCESS])

    created = await client.post(
        f"{_BASE}/",
        json={"name": _KEY_NAME, "expires_in_days": _EXPIRY_DAYS},
        headers=headers,
    )
    assert created.status_code == _CREATED, created.text
    body = created.json()
    assert body["token"].startswith(_TOKEN_PREFIX)
    assert body["prefix"] == body["token"][:_PREFIX_LENGTH]

    listed = await client.get(f"{_BASE}/", headers=headers)
    assert listed.status_code == _OK, listed.text
    keys = listed.json()["keys"]
    assert len(keys) == _ONE_KEY
    assert "token" not in keys[0]
    assert keys[0]["prefix"] == body["prefix"]


@pytest.mark.asyncio
async def test_revoke_is_idempotent_and_404s_the_second_time(client, db):
    headers = _headers([Permissions.MCP_ACCESS])
    created = await client.post(f"{_BASE}/", json={"name": _KEY_NAME}, headers=headers)
    key_id = created.json()["id"]

    first = await client.delete(f"{_BASE}/{key_id}", headers=headers)
    assert first.status_code == _OK, first.text
    second = await client.delete(f"{_BASE}/{key_id}", headers=headers)
    assert second.status_code == _NOT_FOUND


@pytest.mark.asyncio
async def test_a_key_is_visible_and_revocable_only_to_its_owner(client, db):
    owner_headers = _headers([Permissions.MCP_ACCESS])
    stranger_headers = _headers([Permissions.MCP_ACCESS], subject=_OTHER_OWNER)
    created = await client.post(f"{_BASE}/", json={"name": _KEY_NAME}, headers=owner_headers)
    key_id = created.json()["id"]

    stranger_list = await client.get(f"{_BASE}/", headers=stranger_headers)
    assert stranger_list.json()["keys"] == []

    stranger_revoke = await client.delete(f"{_BASE}/{key_id}", headers=stranger_headers)
    assert stranger_revoke.status_code == _NOT_FOUND

    owner_list = await client.get(f"{_BASE}/", headers=owner_headers)
    still_live = owner_list.json()["keys"]
    assert len(still_live) == _ONE_KEY
    assert still_live[0]["revoked_at"] is None


# ANALYZE_ADHOC is the sibling key system's permission: a gate widened to accept either would let
# an ad-hoc key holder mint MCP credentials, and no unrelated permission shows that.
@pytest.mark.parametrize("permissions", [[Permissions.PROJECT_READ], [Permissions.ANALYZE_ADHOC]])
@pytest.mark.asyncio
async def test_missing_permission_is_403(client, db, permissions):
    headers = _headers(permissions)
    resp = await client.post(f"{_BASE}/", json={"name": _KEY_NAME}, headers=headers)
    assert resp.status_code == _FORBIDDEN, resp.text

    listed = await client.get(f"{_BASE}/", headers=headers)
    assert listed.status_code == _FORBIDDEN, listed.text
    assert await _key_count(db) == _NO_KEYS


@pytest.mark.asyncio
async def test_revoking_own_key_without_permission_is_403(client, db):
    # Same subject, so the key is found: without the gate the revoke would succeed, not 404.
    # Unification is expected to drop this gate on the revoke route — a credential must stay
    # revocable by the person it belongs to even once their access to the feature is withdrawn.
    created = await client.post(
        f"{_BASE}/",
        json={"name": _KEY_NAME},
        headers=_headers([Permissions.MCP_ACCESS]),
    )
    key_id = created.json()["id"]

    revoked = await client.delete(f"{_BASE}/{key_id}", headers=_headers([Permissions.PROJECT_READ]))

    assert revoked.status_code == _FORBIDDEN, revoked.text
    still_live = await client.get(f"{_BASE}/", headers=_headers([Permissions.MCP_ACCESS]))
    assert still_live.json()["keys"][0]["revoked_at"] is None


@pytest.mark.asyncio
async def test_a_saturated_listing_names_the_keys_it_did_not_show(client, db):
    """A key the owner cannot see is a key they cannot revoke."""
    headers = _headers([Permissions.MCP_ACCESS])
    repo = MCPApiKeyRepository(db)
    for index in range(LIST_LIMIT + _OVER_THE_PAGE):
        await repo.create(_OWNER, f"{_KEY_NAME}-{index}", _EXPIRY_DAYS)

    listed = await client.get(f"{_BASE}/", headers=headers)

    assert listed.status_code == _OK, listed.text
    body = listed.json()
    assert len(body["keys"]) == LIST_LIMIT
    assert body["truncated"] == {
        "limit": LIST_LIMIT,
        "returned": LIST_LIMIT,
        "total": LIST_LIMIT + _OVER_THE_PAGE,
    }


@pytest.mark.asyncio
async def test_a_complete_listing_declares_no_truncation(client, db):
    headers = _headers([Permissions.MCP_ACCESS])
    await MCPApiKeyRepository(db).create(_OWNER, _KEY_NAME, _EXPIRY_DAYS)

    listed = await client.get(f"{_BASE}/", headers=headers)

    assert listed.json()["truncated"] is None
