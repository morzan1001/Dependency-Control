"""Request/response schemas for the MCP endpoint."""

from typing import Any

from pydantic import BaseModel


class JSONRPCRequest(BaseModel):
    jsonrpc: str = "2.0"
    id: Any | None = None
    method: str
    params: dict[str, Any] | None = None


class JSONRPCError(BaseModel):
    code: int
    message: str
    data: Any | None = None


class JSONRPCResponse(BaseModel):
    jsonrpc: str = "2.0"
    id: Any | None = None
    result: Any | None = None
    error: JSONRPCError | None = None
