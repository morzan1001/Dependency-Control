"""HTTP behaviour of POST /api/v1/mcp.

The route resolves its caller inline from a raw Authorization header rather than through a
dependency, so only a request through the app proves the tool surface is behind a key at all.
"""

import pytest

from app.core.constants import API_KEY_SURFACE_ADHOC, API_KEY_SURFACE_MCP
from app.core.permissions import Permissions
from app.repositories.api_keys import ApiKeyRepository

_MCP = "/api/v1/mcp/"

_OWNER = "mcp-user"
_KEY_NAME = "claude-desktop"
_EXPIRY_DAYS = 30
_REQUEST_ID = 1

_UNIFIED_COL = "api_keys"

_TOOLS_LIST = {"jsonrpc": "2.0", "id": _REQUEST_ID, "method": "tools/list", "params": {}}

_OK = 200
_UNAUTHORIZED = 401
_FORBIDDEN = 403

# An owner holding both permissions leaves the key itself as the only thing that can refuse.
_BOTH_SURFACES = (Permissions.MCP_ACCESS, Permissions.ANALYZE_ADHOC)


async def _seed_owner(db, permissions):
    await db.users.update_one(
        {"_id": _OWNER},
        {
            "$set": {
                "username": _OWNER,
                "email": "mcp@example.com",
                "permissions": list(permissions),
                "is_active": True,
                "hashed_password": "x",
            }
        },
        upsert=True,
    )


async def _issue_unified_key(db, surfaces=(API_KEY_SURFACE_MCP,), permissions=(Permissions.MCP_ACCESS,)):
    doc, plaintext = await ApiKeyRepository(db).create(_OWNER, _KEY_NAME, list(surfaces), _EXPIRY_DAYS)
    await _seed_owner(db, permissions)
    return doc, plaintext


async def _last_used(db, key_id):
    return (await db[_UNIFIED_COL].find_one({"_id": key_id}))["last_used_at"]


def _bearer(token):
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.asyncio
async def test_an_unauthenticated_request_gets_no_tools(client, db):
    resp = await client.post(_MCP, json=_TOOLS_LIST)

    assert resp.status_code == _UNAUTHORIZED, resp.text


@pytest.mark.asyncio
async def test_a_key_whose_owner_lacks_mcp_access_gets_no_tools(client, db):
    # ANALYZE_ADHOC is the sibling surface's permission: a gate widened to accept either would
    # hand every ad-hoc key owner the MCP tool surface.
    _doc, token = await _issue_unified_key(db, permissions=(Permissions.ANALYZE_ADHOC,))

    resp = await client.post(_MCP, json=_TOOLS_LIST, headers=_bearer(token))

    assert resp.status_code == _FORBIDDEN, resp.text


@pytest.mark.asyncio
async def test_a_unified_key_naming_mcp_reaches_the_tool_surface(client, db):
    _doc, token = await _issue_unified_key(db)

    resp = await client.post(_MCP, json=_TOOLS_LIST, headers=_bearer(token))

    assert resp.status_code == _OK, resp.text
    assert resp.json()["result"]["tools"]


@pytest.mark.asyncio
async def test_a_unified_key_that_does_not_name_mcp_gets_no_tools(client, db):
    """The owner holds MCP access, so only the surfaces the key names can turn this caller away."""
    _doc, token = await _issue_unified_key(db, surfaces=(API_KEY_SURFACE_ADHOC,), permissions=_BOTH_SURFACES)

    resp = await client.post(_MCP, json=_TOOLS_LIST, headers=_bearer(token))

    assert resp.status_code == _FORBIDDEN, resp.text


@pytest.mark.asyncio
async def test_a_revoked_unified_key_gets_no_tools(client, db):
    doc, token = await _issue_unified_key(db)
    assert await ApiKeyRepository(db).revoke(doc["_id"], _OWNER), "the key has to actually be revoked"

    resp = await client.post(_MCP, json=_TOOLS_LIST, headers=_bearer(token))

    assert resp.status_code == _UNAUTHORIZED, resp.text


@pytest.mark.asyncio
async def test_admitting_a_unified_key_stamps_its_last_use(client, db):
    doc, token = await _issue_unified_key(db)
    assert await _last_used(db, doc["_id"]) is None, "a fresh key must start unstamped"

    resp = await client.post(_MCP, json=_TOOLS_LIST, headers=_bearer(token))

    assert resp.status_code == _OK, resp.text
    assert await _last_used(db, doc["_id"]) is not None
