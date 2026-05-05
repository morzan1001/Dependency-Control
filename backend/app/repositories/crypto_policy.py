"""
CryptoPolicyRepository — MongoDB access for the `crypto_policies` collection.
"""

from datetime import datetime, timezone

from app.core.metrics import track_db_operation
from app.models.crypto_policy import CryptoPolicy
from app.repositories.base import BaseRepository


class CryptoPolicyRepository(BaseRepository[CryptoPolicy]):
    collection_name = "crypto_policies"
    model_class = CryptoPolicy

    async def get_system_policy(self) -> CryptoPolicy | None:
        with track_db_operation(self.collection_name, "find_one"):
            doc = await self.collection.find_one({"scope": "system", "project_id": None})
        return CryptoPolicy.model_validate(doc) if doc else None

    async def upsert_system_policy(self, policy: CryptoPolicy) -> None:
        assert policy.scope == "system"
        policy.project_id = None
        policy.updated_at = datetime.now(timezone.utc)
        payload = policy.model_dump(by_alias=True, exclude={"id"})
        with track_db_operation(self.collection_name, "update_one"):
            await self.collection.update_one(
                {"scope": "system", "project_id": None},
                {"$set": payload},
                upsert=True,
            )

    async def get_project_policy(self, project_id: str) -> CryptoPolicy | None:
        with track_db_operation(self.collection_name, "find_one"):
            doc = await self.collection.find_one({"scope": "project", "project_id": project_id})
        return CryptoPolicy.model_validate(doc) if doc else None

    async def upsert_project_policy(self, policy: CryptoPolicy) -> None:
        assert policy.scope == "project" and policy.project_id is not None
        policy.updated_at = datetime.now(timezone.utc)
        payload = policy.model_dump(by_alias=True, exclude={"id"})
        with track_db_operation(self.collection_name, "update_one"):
            await self.collection.update_one(
                {"scope": "project", "project_id": policy.project_id},
                {"$set": payload},
                upsert=True,
            )

    async def delete_project_policy(self, project_id: str) -> None:
        with track_db_operation(self.collection_name, "delete_one"):
            await self.collection.delete_one({"scope": "project", "project_id": project_id})
