"""MongoDB persistence for ad-hoc analysis API keys."""

import hashlib
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from motor.motor_asyncio import AsyncIOMotorDatabase
from pymongo import ReadPreference

from app.core.metrics import track_db_operation

_COL = "adhoc_api_keys"

# Token format "dca_<body>": prefix aids recognition in logs; body is url-safe entropy.
_TOKEN_PREFIX = "dca_"
_TOKEN_BODY_BYTES = 48
_TOKEN_BODY_CHARS = 64
_PREFIX_BODY_CHARS = 8

_MIN_EXPIRY_DAYS = 1
_MAX_EXPIRY_DAYS = 365
LIST_LIMIT = 100


def generate_plaintext_token() -> str:
    body = secrets.token_urlsafe(_TOKEN_BODY_BYTES).replace("-", "").replace("_", "")
    return _TOKEN_PREFIX + body[:_TOKEN_BODY_CHARS]


def hash_token(plaintext: str) -> str:
    return hashlib.sha256(plaintext.encode("utf-8")).hexdigest()


class AdhocApiKeyRepository:
    """Ad-hoc keys carry no usage timestamp: authenticating an ad-hoc request must not write."""

    def __init__(self, db: AsyncIOMotorDatabase):
        self.db = db
        self.collection = db[_COL]

    async def create(self, user_id: str, name: str, expires_in_days: int) -> tuple[dict[str, Any], str]:
        """Returns (stored_document, plaintext_token); the plaintext is shown once and never persisted."""
        token = generate_plaintext_token()
        clamped_days = max(_MIN_EXPIRY_DAYS, min(expires_in_days, _MAX_EXPIRY_DAYS))
        now = datetime.now(timezone.utc)
        doc: dict[str, Any] = {
            "_id": str(uuid.uuid4()),
            "user_id": user_id,
            "name": name,
            "prefix": token[: len(_TOKEN_PREFIX) + _PREFIX_BODY_CHARS],
            "token_hash": hash_token(token),
            "created_at": now,
            "expires_at": now + timedelta(days=clamped_days),
            "revoked_at": None,
        }
        with track_db_operation(_COL, "insert"):
            await self.collection.insert_one(doc)
        return doc, token

    async def list_for_user(self, user_id: str) -> tuple[list[dict[str, Any]], int]:
        """The newest page of the user's keys and how many they hold; the count costs a round
        trip only once the page saturates, which is the only time the two differ."""
        query = {"user_id": user_id}
        with track_db_operation(_COL, "find"):
            cursor = self.collection.find(query, sort=[("created_at", -1)])
            docs: list[dict[str, Any]] = await cursor.to_list(length=LIST_LIMIT)
        if len(docs) < LIST_LIMIT:
            return docs, len(docs)
        with track_db_operation(_COL, "count"):
            return docs, await self.collection.count_documents(query)

    async def get_by_plaintext(self, plaintext: str) -> dict[str, Any] | None:
        if not plaintext.startswith(_TOKEN_PREFIX):
            return None
        now = datetime.now(timezone.utc)
        # Strong read: a revoked key must stop authenticating immediately.
        primary = self.collection.with_options(read_preference=ReadPreference.PRIMARY)  # type: ignore[arg-type]
        with track_db_operation(_COL, "find_one"):
            doc: dict[str, Any] | None = await primary.find_one(
                {
                    "token_hash": hash_token(plaintext),
                    "revoked_at": None,
                    "expires_at": {"$gt": now},
                }
            )
        return doc

    async def revoke(self, key_id: str, user_id: str) -> bool:
        """Idempotent revoke of a key the user owns."""
        with track_db_operation(_COL, "update"):
            result = await self.collection.update_one(
                {"_id": key_id, "user_id": user_id, "revoked_at": None},
                {"$set": {"revoked_at": datetime.now(timezone.utc)}},
            )
        return bool(result.modified_count > 0)
