"""MCP JSON-RPC 2.0 endpoint (protocol 2025-03-26); external LLM clients authenticate with an MCP API key and call the chat tool registry under the key owner's permissions."""

from __future__ import annotations

import json
import logging
from typing import Any, Dict

from fastapi import Header, HTTPException, Request, status
from fastapi.responses import JSONResponse
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.api.deps import DatabaseDep
from app.api.router import CustomAPIRouter
from app.core.permissions import Permissions, has_permission
from app.models.user import User
from app.repositories.mcp_api_keys import MCPApiKeyRepository
from app.repositories.users import UserRepository
from app.services.chat.tools import ChatToolRegistry, get_tool_definitions

logger = logging.getLogger(__name__)

router = CustomAPIRouter()

SERVER_NAME = "dependency-control"
SERVER_VERSION = "1.0"
MCP_PROTOCOL_VERSION = "2025-03-26"

_PARSE_ERROR = -32700
_INVALID_REQUEST = -32600
_METHOD_NOT_FOUND = -32601
_INVALID_PARAMS = -32602
_INTERNAL_ERROR = -32603


def _rpc_error(code: int, message: str, request_id: Any = None) -> Dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {"code": code, "message": message},
    }


def _rpc_result(result: Any, request_id: Any) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


class _RpcError(Exception):
    """Raised inside dispatch to signal a JSON-RPC error response."""

    def __init__(self, code: int, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


async def _resolve_user_from_token(authorization: str, db: "AsyncIOMotorDatabase[Any]") -> tuple[User, Dict[str, Any]]:
    """Validate Bearer token and return the (user, key_doc) pair; raises HTTPException on failure."""
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Bearer token",
            headers={"WWW-Authenticate": 'Bearer realm="mcp"'},
        )
    token = authorization.split(" ", 1)[1].strip()
    key_repo = MCPApiKeyRepository(db)
    key_doc = await key_repo.get_by_plaintext(token)
    if not key_doc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid, revoked, or expired MCP API key",
        )
    user_repo = UserRepository(db)
    user = await user_repo.get_by_id(key_doc["user_id"])
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token owner is no longer active",
        )
    if not has_permission(user.permissions, Permissions.MCP_ACCESS):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Token owner no longer has MCP access",
        )
    await key_repo.touch_last_used(key_doc["_id"])
    return user, key_doc


def _tools_list_payload() -> Dict[str, Any]:
    """Map our TOOL_DEFINITIONS (OpenAI-style) into MCP tool shape."""
    tools = []
    for td in get_tool_definitions():
        fn = td.get("function", {})
        tools.append(
            {
                "name": fn.get("name", ""),
                "description": fn.get("description", ""),
                "inputSchema": fn.get("parameters", {"type": "object", "properties": {}}),
            }
        )
    return {"tools": tools}


async def _handle_tool_call(
    registry: ChatToolRegistry,
    params: Dict[str, Any],
    user: User,
    db: "AsyncIOMotorDatabase[Any]",
) -> Dict[str, Any]:
    """Execute a tool call for MCP; protocol errors raise _RpcError, execution errors return isError=true."""
    name = params.get("name")
    if not isinstance(name, str) or not name:
        raise _RpcError(_INVALID_PARAMS, "Missing 'name' in tools/call params")
    arguments = params.get("arguments") or {}
    if not isinstance(arguments, dict):
        raise _RpcError(_INVALID_PARAMS, "'arguments' must be an object")

    available = registry.get_available_tool_names(user.permissions)
    if name not in available:
        raise _RpcError(_METHOD_NOT_FOUND, f"Tool '{name}' is not available")

    result = await registry.execute_tool(name, arguments, user, db)
    text = json.dumps(result, default=str, ensure_ascii=False, indent=2)
    is_error = isinstance(result, dict) and "error" in result
    return {
        "content": [{"type": "text", "text": text}],
        "isError": is_error,
    }


async def _dispatch(method: str, params: Dict[str, Any], user: User, db: "AsyncIOMotorDatabase[Any]") -> Any:
    if method == "initialize":
        # Echo our protocol version and advertise only 'tools'.
        return {
            "protocolVersion": MCP_PROTOCOL_VERSION,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
            "instructions": (
                "Dependency Control SBOM security platform. Tool calls run in "
                "the context of the API key owner and honour that user's "
                "project-level authorization."
            ),
        }

    if method == "initialized" or method == "notifications/initialized":
        return None

    if method == "ping":
        return {}

    if method == "tools/list":
        registry = ChatToolRegistry()
        available = registry.get_available_tool_names(user.permissions)
        payload = _tools_list_payload()
        payload["tools"] = [t for t in payload["tools"] if t["name"] in available]
        return payload

    if method == "tools/call":
        registry = ChatToolRegistry()
        return await _handle_tool_call(registry, params, user, db)

    raise ValueError(f"Unknown method: {method}")


@router.post(
    "",
    summary="MCP JSON-RPC endpoint",
    description=(
        "Model Context Protocol endpoint for external LLM clients. "
        "Authenticate with an MCP API key in the Authorization: Bearer header."
    ),
)
@router.post("/", include_in_schema=False)
async def mcp_rpc(
    request: Request,
    db: DatabaseDep,
    authorization: str = Header(default=""),
) -> Any:
    user, _ = await _resolve_user_from_token(authorization, db)

    try:
        payload = await request.json()
    except Exception:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content=_rpc_error(_PARSE_ERROR, "Invalid JSON"),
        )

    # Spec allows a JSON array of batched requests; handle uniformly.
    batched = isinstance(payload, list)
    requests = payload if batched else [payload]

    responses = []
    for item in requests:
        if not isinstance(item, dict):
            responses.append(_rpc_error(_INVALID_REQUEST, "Request must be an object"))
            continue

        request_id = item.get("id")
        method = item.get("method")
        params = item.get("params") or {}
        if not isinstance(method, str):
            responses.append(_rpc_error(_INVALID_REQUEST, "Missing 'method'", request_id))
            continue

        try:
            result = await _dispatch(method, params, user, db)
        except _RpcError as e:
            if request_id is not None:
                responses.append(_rpc_error(e.code, e.message, request_id))
            continue
        except ValueError as e:
            if request_id is not None:
                responses.append(_rpc_error(_METHOD_NOT_FOUND, str(e), request_id))
            continue
        except Exception:
            logger.exception("MCP dispatch failed for method=%s", method)
            if request_id is not None:
                responses.append(_rpc_error(_INTERNAL_ERROR, "Internal server error", request_id))
            continue

        if request_id is None:
            continue

        responses.append(_rpc_result(result, request_id))

    # Notifications (no id) get no response; 202 if every item was a notification.
    if not responses:
        return JSONResponse(status_code=status.HTTP_202_ACCEPTED, content=None)
    if batched:
        return JSONResponse(content=responses)
    return JSONResponse(content=responses[0])
