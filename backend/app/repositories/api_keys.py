"""MongoDB persistence for API keys, each naming the surfaces it may enter."""

import hashlib
import logging
import secrets
import string
import uuid
from collections.abc import Sequence
from datetime import datetime, timedelta, timezone
from typing import Any

from motor.motor_asyncio import AsyncIOMotorDatabase
from pymongo import ReadPreference

from app.core.constants import API_KEY_SURFACES
from app.core.metrics import track_db_operation

logger = logging.getLogger(__name__)

_COL = "api_keys"

# Token format "dck_<body>": the prefix aids recognition in logs.
_TOKEN_PREFIX = "dck_"
_TOKEN_ALPHABET = string.ascii_letters + string.digits
_TOKEN_BODY_CHARS = 64
_PREFIX_BODY_CHARS = 8

_MIN_EXPIRY_DAYS = 1
_MAX_EXPIRY_DAYS = 365
LIST_LIMIT = 100


def generate_plaintext_token() -> str:
    """Fixed length: a punctuation-free alphabet needs no stripping, which is what varies the
    body elsewhere."""
    return _TOKEN_PREFIX + "".join(secrets.choice(_TOKEN_ALPHABET) for _ in range(_TOKEN_BODY_CHARS))


def hash_token(plaintext: str) -> str:
    return hashlib.sha256(plaintext.encode("utf-8")).hexdigest()


class ApiKeyRepository:
    def __init__(self, db: AsyncIOMotorDatabase):
        self.db = db
        self.collection = db[_COL]

    async def create(
        self,
        user_id: str,
        name: str,
        surfaces: Sequence[str],
        expires_in_days: int,
    ) -> tuple[dict[str, Any], str]:
        """Returns (stored_document, plaintext_token); the plaintext is shown once and never persisted."""
        requested = list(dict.fromkeys(surfaces))
        unknown = [surface for surface in requested if surface not in API_KEY_SURFACES]
        if unknown or not requested:
            raise ValueError(f"surfaces must be a non-empty subset of {sorted(API_KEY_SURFACES)}")

        token = generate_plaintext_token()
        clamped_days = max(_MIN_EXPIRY_DAYS, min(expires_in_days, _MAX_EXPIRY_DAYS))
        now = datetime.now(timezone.utc)
        doc: dict[str, Any] = {
            "_id": str(uuid.uuid4()),
            "user_id": user_id,
            "name": name,
            "surfaces": requested,
            "prefix": token[: len(_TOKEN_PREFIX) + _PREFIX_BODY_CHARS],
            "token_hash": hash_token(token),
            "created_at": now,
            "expires_at": now + timedelta(days=clamped_days),
            "last_used_at": None,
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
        # Strong read: fresh keys must auth immediately, revoked keys must stop immediately.
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

    async def touch_last_used(self, key_id: str) -> None:
        """Best-effort; a failed usage stamp must not fail the request it was recording."""
        try:
            with track_db_operation(_COL, "update"):
                await self.collection.update_one(
                    {"_id": key_id},
                    {"$set": {"last_used_at": datetime.now(timezone.utc)}},
                )
        except Exception:
            logger.debug("Failed to update last_used_at for API key %s", key_id, exc_info=True)
