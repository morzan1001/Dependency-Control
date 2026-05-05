"""MCP API key models.

External MCP clients (Claude Desktop, Cursor, custom bots) authenticate
against /api/v1/mcp with a personal access token issued here. Tokens are
scoped to a single user — the tool registry then applies the user's
existing project / permission scope on every tool call.

The plaintext token is shown to the user exactly once at creation time;
MongoDB stores only the SHA-256 hash, so a DB leak does not hand out
working tokens. Tokens carry a mandatory expiration date (max 365 days,
default 90).
"""

import uuid
from datetime import datetime
from typing import Optional

from pydantic import ConfigDict, Field

from app.models.base import CreatedAtModel
from app.models.types import PyObjectId


class MCPApiKey(CreatedAtModel):
    id: PyObjectId = Field(
        default_factory=lambda: str(uuid.uuid4()),
        validation_alias="_id",
        serialization_alias="_id",
    )
    user_id: str
    name: str  # user-supplied label, e.g. "Claude Desktop"
    prefix: str  # first 12 chars of the plaintext token, for UI identification
    token_hash: str  # sha256 of the full plaintext token
    expires_at: datetime
    last_used_at: Optional[datetime] = None
    revoked_at: Optional[datetime] = None

    model_config = ConfigDict(populate_by_name=True)
