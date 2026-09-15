"""Request/response schemas for the MCP endpoint."""

from typing import Any

from pydantic import BaseModel


class JSONRPCError(BaseModel):
    code: int
    message: str
    data: Any | None = None
