"""
CryptoPolicyRepository — MongoDB access for the `crypto_policies` collection.
"""

from datetime import datetime, timezone
from typing import Optional

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.models.crypto_policy import CryptoPolicy


class CryptoPolicyRepository:
    COLLECTION = "crypto_policies"

    def __init__(self, db: AsyncIOMotorDatabase):
        self._col = db[self.COLLECTION]

    async def ensure_indexes(self) -> None:
        await self._col.create_index(
            [("scope", 1), ("project_id", 1)], unique=True
        )

    async def get_system_policy(self) -> Optional[CryptoPolicy]:
        doc = await self._col.find_one({"scope": "system", "project_id": None})
        return CryptoPolicy.model_validate(doc) if doc else None

    async def upsert_system_policy(self, policy: CryptoPolicy) -> None:
        assert policy.scope == "system"
        policy.project_id = None
        policy.updated_at = datetime.now(timezone.utc)
        payload = policy.model_dump(by_alias=True, exclude={"id"})
        await self._col.update_one(
            {"scope": "system", "project_id": None},
            {"$set": payload},
            upsert=True,
        )

    async def get_project_policy(self, project_id: str) -> Optional[CryptoPolicy]:
        doc = await self._col.find_one(
            {"scope": "project", "project_id": project_id}
        )
        return CryptoPolicy.model_validate(doc) if doc else None

    async def upsert_project_policy(self, policy: CryptoPolicy) -> None:
        assert policy.scope == "project" and policy.project_id is not None
        policy.updated_at = datetime.now(timezone.utc)
        payload = policy.model_dump(by_alias=True, exclude={"id"})
        await self._col.update_one(
            {"scope": "project", "project_id": policy.project_id},
            {"$set": payload},
            upsert=True,
        )

    async def delete_project_policy(self, project_id: str) -> None:
        await self._col.delete_one(
            {"scope": "project", "project_id": project_id}
        )
