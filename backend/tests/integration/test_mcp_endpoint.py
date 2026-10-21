"""The route resolves its caller through the MCP key dependency, so only a request through the app proves the gate."""

import pytest

from app.api.v1.endpoints.mcp import MCP_MAX_BATCH_SIZE
from app.core import metrics
from app.core.constants import API_KEY_SURFACE_ADHOC, API_KEY_SURFACE_MCP
from app.core.permissions import Permissions
from app.repositories.api_keys import ApiKeyRepository
from app.services.chat import rate_limiter
from app.services.chat.tools import ChatToolRegistry
from app.services.chat.tools._helpers import MAX_TOOL_RESULT_BYTES, _json_size

_MCP = "/api/v1/mcp/"

_OWNER = "mcp-user"
_KEY_NAME = "claude-desktop"
_EXPIRY_DAYS = 30
_REQUEST_ID = 1

_UNIFIED_COL = "api_keys"

_TOOLS_LIST = {"jsonrpc": "2.0", "id": _REQUEST_ID, "method": "tools/list", "params": {}}

_OK = 200
_ACCEPTED = 202
_BAD_REQUEST = 400
_UNAUTHORIZED = 401
_FORBIDDEN = 403

_RATE_LIMITED = -32000
_INVALID_REQUEST = -32600
_METHOD_NOT_FOUND = -32601
_INVALID_PARAMS = -32602
_INTERNAL_ERROR = -32603

# An owner holding both permissions leaves the key itself as the only thing that can refuse.
_BOTH_SURFACES = (Permissions.MCP_ACCESS, Permissions.ANALYZE_ADHOC)

_CHAT_DENIALS = "dc_chat_rate_limited_total"


@pytest.fixture(autouse=True)
def limiter_cache(fake_cache, monkeypatch):
    monkeypatch.setattr(rate_limiter, "cache_service", fake_cache)
    return fake_cache


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
    # A gate widened to accept the sibling surface's permission would hand every ad-hoc key owner MCP.
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
async def test_a_retired_mcp_key_is_told_to_switch_to_a_dck_key(client, db):
    resp = await client.post(_MCP, json=_TOOLS_LIST, headers=_bearer("mcp_" + "a" * 64))

    assert resp.status_code == _UNAUTHORIZED, resp.text
    assert "dck_" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_admitting_a_unified_key_stamps_its_last_use(client, db):
    doc, token = await _issue_unified_key(db)
    assert await _last_used(db, doc["_id"]) is None, "a fresh key must start unstamped"

    resp = await client.post(_MCP, json=_TOOLS_LIST, headers=_bearer(token))

    assert resp.status_code == _OK, resp.text
    assert await _last_used(db, doc["_id"]) is not None


@pytest.mark.asyncio
async def test_the_catalogue_hides_a_tool_the_key_owner_may_not_call(client, db):
    """tools/call refuses it anyway, so advertising it would only name the deployment's privileged tools."""
    _doc, token = await _issue_unified_key(db)

    resp = await client.post(_MCP, json=_TOOLS_LIST, headers=_bearer(token))

    names = {tool["name"] for tool in resp.json()["result"]["tools"]}
    # get_system_settings is gated on system:manage, which this owner does not hold.
    assert "get_system_settings" not in names
    assert "list_projects" in names


@pytest.mark.asyncio
async def test_an_advertised_tool_carries_the_arguments_it_requires(client, db):
    """An MCP client builds its call from inputSchema alone."""
    _doc, token = await _issue_unified_key(db)

    resp = await client.post(_MCP, json=_TOOLS_LIST, headers=_bearer(token))

    schemas = {tool["name"]: tool["inputSchema"] for tool in resp.json()["result"]["tools"]}
    assert "project_id" in schemas["get_project_details"]["properties"]
    assert schemas["get_project_details"]["required"] == ["project_id"]


@pytest.mark.asyncio
async def test_results_and_errors_of_one_batch_share_the_json_rpc_version(client, db):
    """Separate helpers build the two envelopes, and a JSON-RPC 2.0 client discards whichever version drifts."""
    _doc, token = await _issue_unified_key(db)

    resp = await client.post(
        _MCP,
        json=[_TOOLS_LIST, {"jsonrpc": "2.0", "id": 2, "method": "no/such/method"}],
        headers=_bearer(token),
    )

    body = resp.json()
    assert [item["id"] for item in body] == [_REQUEST_ID, 2]
    assert "result" in body[0] and "error" in body[1]
    assert {item["jsonrpc"] for item in body} == {"2.0"}


async def _rpc(client, db, payload):
    _doc, token = await _issue_unified_key(db)
    return await client.post(_MCP, json=payload, headers=_bearer(token))


@pytest.mark.asyncio
async def test_a_notification_gets_202_without_a_body(client, db):
    resp = await _rpc(client, db, {"jsonrpc": "2.0", "method": "notifications/initialized"})

    assert resp.status_code == _ACCEPTED, resp.text


@pytest.mark.asyncio
async def test_a_request_without_a_method_is_invalid_with_a_null_id(client, db):
    resp = await _rpc(client, db, {"jsonrpc": "2.0"})

    assert resp.json() == {
        "jsonrpc": "2.0",
        "id": None,
        "error": {"code": _INVALID_REQUEST, "message": "Missing 'method'"},
    }


@pytest.mark.asyncio
@pytest.mark.parametrize("params", [["name"], [], "", 0, False, None])
async def test_params_that_are_not_an_object_are_invalid_params(client, db, params):
    resp = await _rpc(client, db, {"jsonrpc": "2.0", "id": _REQUEST_ID, "method": "tools/list", "params": params})

    assert resp.json()["error"]["code"] == _INVALID_PARAMS


@pytest.mark.asyncio
async def test_the_bare_initialized_name_is_an_unknown_method(client, db):
    resp = await _rpc(client, db, {"jsonrpc": "2.0", "id": _REQUEST_ID, "method": "initialized"})

    assert resp.json()["error"]["code"] == _METHOD_NOT_FOUND


@pytest.mark.asyncio
async def test_a_tool_result_that_cannot_be_serialised_is_an_internal_error(client, db, monkeypatch):
    circular: dict = {}
    circular["self"] = circular

    async def _circular_result(*_args):
        return circular

    monkeypatch.setattr(ChatToolRegistry, "execute_tool", _circular_result)

    resp = await _rpc(
        client,
        db,
        {"jsonrpc": "2.0", "id": _REQUEST_ID, "method": "tools/call", "params": {"name": "list_projects"}},
    )

    assert resp.json()["error"] == {"code": _INTERNAL_ERROR, "message": "Internal server error"}


@pytest.mark.asyncio
async def test_initialize_reports_the_release_version(client, db):
    resp = await _rpc(client, db, {"jsonrpc": "2.0", "id": _REQUEST_ID, "method": "initialize", "params": {}})

    assert resp.json()["result"]["serverInfo"]["version"] == metrics.APP_VERSION


def _tool_call(request_id):
    return {"jsonrpc": "2.0", "id": request_id, "method": "tools/call", "params": {"name": "list_projects"}}


async def _admit_one_chat_message(db, tool_rounds, window="chat_rate_limit_per_minute"):
    await db.system_settings.insert_one({"_id": "current", window: 1, "chat_max_tool_rounds": tool_rounds})


@pytest.mark.asyncio
@pytest.mark.parametrize("length", [0, MCP_MAX_BATCH_SIZE + 1])
async def test_a_batch_outside_the_cap_is_refused_whole_as_an_invalid_request(client, db, monkeypatch, length):
    executed: list[str] = []

    async def _record(_self, name, *_args):
        executed.append(name)
        return {}

    monkeypatch.setattr(ChatToolRegistry, "execute_tool", _record)

    resp = await _rpc(client, db, [_tool_call(i) for i in range(length)])

    assert resp.status_code == _BAD_REQUEST, resp.text
    body = resp.json()
    assert (body["id"], body["error"]["code"]) == (None, _INVALID_REQUEST)
    assert str(MCP_MAX_BATCH_SIZE) in body["error"]["message"]
    assert executed == []


@pytest.mark.asyncio
async def test_a_batch_at_the_cap_is_answered_in_full(client, db):
    resp = await _rpc(client, db, [{"jsonrpc": "2.0", "id": i, "method": "ping"} for i in range(MCP_MAX_BATCH_SIZE)])

    assert resp.status_code == _OK, resp.text
    assert [item["id"] for item in resp.json()] == list(range(MCP_MAX_BATCH_SIZE))


@pytest.mark.asyncio
@pytest.mark.parametrize("window", ["chat_rate_limit_per_minute", "chat_rate_limit_per_hour"])
async def test_tool_calls_beyond_the_owners_window_get_a_json_rpc_error_each(client, db, window):
    """One chat message may run chat_max_tool_rounds tool rounds, so it buys that many calls."""
    await _admit_one_chat_message(db, tool_rounds=2, window=window)
    chat_denials = metrics.REGISTRY.get_sample_value(_CHAT_DENIALS)

    resp = await _rpc(client, db, [_tool_call(1), _tool_call(2), _tool_call(3)])

    assert resp.status_code == _OK, resp.text
    first, second, third = resp.json()
    assert "result" in first and "result" in second
    assert third["id"] == 3
    assert third["error"]["code"] == _RATE_LIMITED
    assert "retry in" in third["error"]["message"]
    assert metrics.REGISTRY.get_sample_value(_CHAT_DENIALS) == chat_denials


@pytest.mark.asyncio
async def test_a_rate_limited_owner_still_completes_the_handshake(client, db):
    await _admit_one_chat_message(db, tool_rounds=1)
    _doc, token = await _issue_unified_key(db)
    await client.post(_MCP, json=_tool_call(1), headers=_bearer(token))

    resp = await client.post(
        _MCP,
        json=[
            {"jsonrpc": "2.0", "id": 2, "method": "initialize", "params": {}},
            _TOOLS_LIST,
            {"jsonrpc": "2.0", "id": 3, "method": "ping"},
            _tool_call(4),
        ],
        headers=_bearer(token),
    )

    initialize, tools, ping, call = resp.json()
    assert "result" in initialize and "result" in tools and "result" in ping
    assert call["error"]["code"] == _RATE_LIMITED


@pytest.mark.asyncio
async def test_every_key_of_one_owner_draws_on_the_owners_window(client, db):
    await _admit_one_chat_message(db, tool_rounds=1)
    _first_doc, first = await _issue_unified_key(db)
    _second_doc, second = await _issue_unified_key(db)

    allowed = await client.post(_MCP, json=_tool_call(1), headers=_bearer(first))
    refused = await client.post(_MCP, json=_tool_call(2), headers=_bearer(second))

    assert "result" in allowed.json()
    assert refused.json()["error"]["code"] == _RATE_LIMITED


@pytest.mark.asyncio
async def test_spending_the_mcp_window_leaves_the_chat_window_untouched(client, db):
    await _admit_one_chat_message(db, tool_rounds=1)
    _doc, token = await _issue_unified_key(db)
    await client.post(_MCP, json=_tool_call(1), headers=_bearer(token))
    refused = await client.post(_MCP, json=_tool_call(2), headers=_bearer(token))
    assert refused.json()["error"]["code"] == _RATE_LIMITED

    assert await rate_limiter.rate_limit_retry_after(_OWNER, per_minute=1, per_hour=1) == 0


@pytest.mark.asyncio
async def test_a_tool_result_reaches_the_client_in_the_size_the_budget_measured(client, db, monkeypatch):
    rows = {"rows": [{"name": f"pkg-{i}", "version": "1.0.0"} for i in range(160)]}
    assert _json_size(rows) <= MAX_TOOL_RESULT_BYTES

    async def _result(*_args):
        return rows

    monkeypatch.setattr(ChatToolRegistry, "execute_tool", _result)

    resp = await _rpc(
        client,
        db,
        {"jsonrpc": "2.0", "id": _REQUEST_ID, "method": "tools/call", "params": {"name": "list_projects"}},
    )

    (content,) = resp.json()["result"]["content"]
    assert len(content["text"].encode()) == _json_size(rows)
