"""Request/response schemas for MCP API key management and the MCP endpoint."""

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field


class MCPKeyCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=80)
    expires_in_days: int = Field(90, ge=1, le=365)


class MCPKeyResponse(BaseModel):
    id: str
    name: str
    prefix: str
    created_at: datetime
    expires_at: datetime
    last_used_at: Optional[datetime] = None
    revoked_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True, populate_by_name=True)


class MCPKeyCreateResponse(MCPKeyResponse):
    """Returned only at creation — contains the plaintext token."""

    token: str = Field(
        ...,
        description=(
            "The plaintext API key. Shown exactly once — the server only "
            "keeps a SHA-256 hash. If you lose it, revoke this key and "
            "create a new one."
        ),
    )


class MCPKeyListResponse(BaseModel):
    keys: List[MCPKeyResponse]


# ── MCP JSON-RPC 2.0 envelope types ─────────────────────────────────────

class JSONRPCRequest(BaseModel):
    jsonrpc: str = "2.0"
    id: Optional[Any] = None
    method: str
    params: Optional[Dict[str, Any]] = None


class JSONRPCError(BaseModel):
    code: int
    message: str
    data: Optional[Any] = None


class JSONRPCResponse(BaseModel):
    jsonrpc: str = "2.0"
    id: Optional[Any] = None
    result: Optional[Any] = None
    error: Optional[JSONRPCError] = None
