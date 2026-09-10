"""HTTP behaviour of POST /api/v1/mcp.

The route resolves its caller inline from a raw Authorization header rather than through a
dependency, so only a request through the app proves the tool surface is behind a key at all.
"""

import pytest

from app.core.permissions import Permissions
from app.repositories.mcp_api_keys import MCPApiKeyRepository

_MCP = "/api/v1/mcp/"

_OWNER = "mcp-user"
_KEY_NAME = "claude-desktop"
_EXPIRY_DAYS = 30
_REQUEST_ID = 1

_TOOLS_LIST = {"jsonrpc": "2.0", "id": _REQUEST_ID, "method": "tools/list", "params": {}}

_OK = 200
_UNAUTHORIZED = 401
_FORBIDDEN = 403


async def _issue_key(db, permissions=(Permissions.MCP_ACCESS,)):
    doc, plaintext = await MCPApiKeyRepository(db).create(_OWNER, _KEY_NAME, _EXPIRY_DAYS)
    await db.users.insert_one(
        {
            "_id": _OWNER,
            "username": _OWNER,
            "email": "mcp@example.com",
            "permissions": list(permissions),
            "is_active": True,
            "hashed_password": "x",
        }
    )
    return doc, plaintext


def _bearer(token):
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.asyncio
async def test_a_live_key_reaches_the_tool_surface(client, db):
    _, token = await _issue_key(db)

    resp = await client.post(_MCP, json=_TOOLS_LIST, headers=_bearer(token))

    assert resp.status_code == _OK, resp.text
    assert resp.json()["result"]["tools"]


@pytest.mark.asyncio
async def test_an_unauthenticated_request_gets_no_tools(client, db):
    resp = await client.post(_MCP, json=_TOOLS_LIST)

    assert resp.status_code == _UNAUTHORIZED, resp.text


@pytest.mark.asyncio
async def test_a_revoked_key_gets_no_tools(client, db):
    doc, token = await _issue_key(db)
    await MCPApiKeyRepository(db).revoke(doc["_id"], _OWNER)

    resp = await client.post(_MCP, json=_TOOLS_LIST, headers=_bearer(token))

    assert resp.status_code == _UNAUTHORIZED, resp.text


@pytest.mark.asyncio
async def test_a_key_whose_owner_lacks_mcp_access_gets_no_tools(client, db):
    # ANALYZE_ADHOC is the sibling key system's permission: a gate widened to accept either would
    # hand every ad-hoc key owner the MCP tool surface.
    _, token = await _issue_key(db, permissions=(Permissions.ANALYZE_ADHOC,))

    resp = await client.post(_MCP, json=_TOOLS_LIST, headers=_bearer(token))

    assert resp.status_code == _FORBIDDEN, resp.text
