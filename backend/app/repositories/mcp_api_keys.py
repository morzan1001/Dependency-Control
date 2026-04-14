"""MongoDB persistence for MCP API keys."""

import hashlib
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.core.metrics import track_db_operation

_COL = "mcp_api_keys"

# Plaintext token format: "mcp_<hex>" — 'mcp_' prefix makes it easy to
# recognise in logs and CLI output; the hex body is 64 chars of url-safe
# entropy (≈ 384 bits).
_TOKEN_PREFIX = "mcp_"
_TOKEN_BODY_BYTES = 48  # → 64 chars once token_urlsafe() encodes it


def generate_plaintext_token() -> str:
    return _TOKEN_PREFIX + secrets.token_urlsafe(_TOKEN_BODY_BYTES).replace("-", "").replace("_", "")[:64]


def hash_token(plaintext: str) -> str:
    return hashlib.sha256(plaintext.encode("utf-8")).hexdigest()


class MCPApiKeyRepository:
    def __init__(self, db: AsyncIOMotorDatabase):
        self.db = db
        self.collection = db[_COL]

    async def create(
        self,
        user_id: str,
        name: str,
        expires_in_days: int,
    ) -> Tuple[Dict[str, Any], str]:
        """Create a new key. Returns (stored_document, plaintext_token).

        The plaintext token is shown to the caller once and must never be
        persisted anywhere other than the client who asked for it.
        """
        token = generate_plaintext_token()
        doc = {
            "_id": str(uuid.uuid4()),
            "user_id": user_id,
            "name": name,
            "prefix": token[: len(_TOKEN_PREFIX) + 8],  # e.g. "mcp_aBcDeFgH"
            "token_hash": hash_token(token),
            "created_at": datetime.now(timezone.utc),
            "expires_at": datetime.now(timezone.utc)
            + timedelta(days=max(1, min(expires_in_days, 365))),
            "last_used_at": None,
            "revoked_at": None,
        }
        with track_db_operation(_COL, "insert"):
            await self.collection.insert_one(doc)
        return doc, token

    async def list_for_user(self, user_id: str) -> List[Dict[str, Any]]:
        with track_db_operation(_COL, "find"):
            cursor = self.collection.find(
                {"user_id": user_id}, sort=[("created_at", -1)]
            )
            return await cursor.to_list(length=100)

    async def get_by_plaintext(self, plaintext: str) -> Optional[Dict[str, Any]]:
        """Look up an active key by its presented plaintext token.

        Returns None if the key is unknown, revoked, or expired.
        """
        if not plaintext.startswith(_TOKEN_PREFIX):
            return None
        now = datetime.now(timezone.utc)
        with track_db_operation(_COL, "find_one"):
            doc = await self.collection.find_one(
                {
                    "token_hash": hash_token(plaintext),
                    "revoked_at": None,
                    "expires_at": {"$gt": now},
                }
            )
        return doc

    async def revoke(self, key_id: str, user_id: str) -> bool:
        """Revoke a key the user owns. Idempotent."""
        with track_db_operation(_COL, "update"):
            result = await self.collection.update_one(
                {"_id": key_id, "user_id": user_id, "revoked_at": None},
                {"$set": {"revoked_at": datetime.now(timezone.utc)}},
            )
        return result.modified_count > 0

    async def touch_last_used(self, key_id: str) -> None:
        """Best-effort update of last_used_at — failures here must not block
        the actual MCP request, so we swallow errors silently."""
        try:
            with track_db_operation(_COL, "update"):
                await self.collection.update_one(
                    {"_id": key_id},
                    {"$set": {"last_used_at": datetime.now(timezone.utc)}},
                )
        except Exception:
            pass
