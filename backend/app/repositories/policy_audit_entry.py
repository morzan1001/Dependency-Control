"""
PolicyAuditRepository — MongoDB access for `crypto_policy_history`.
"""

from datetime import datetime
from typing import List, Literal, Optional

from motor.motor_asyncio import AsyncIOMotorDatabase
from pymongo import DESCENDING

from app.models.policy_audit_entry import PolicyAuditEntry


class PolicyAuditRepository:
    COLLECTION = "crypto_policy_history"

    def __init__(self, db: AsyncIOMotorDatabase):
        self._col = db[self.COLLECTION]

    async def ensure_indexes(self) -> None:
        await self._col.create_index(
            [("policy_scope", 1), ("project_id", 1), ("version", -1)]
        )
        await self._col.create_index([("timestamp", -1)])
        await self._col.create_index([("actor_user_id", 1), ("timestamp", -1)])

    async def insert(self, entry: PolicyAuditEntry) -> None:
        await self._col.insert_one(entry.model_dump(by_alias=True))

    async def list(
        self,
        *,
        policy_scope: Literal["system", "project"],
        project_id: Optional[str] = None,
        skip: int = 0,
        limit: int = 50,
    ) -> List[PolicyAuditEntry]:
        query = {"policy_scope": policy_scope, "project_id": project_id}
        cursor = (
            self._col.find(query)
            .sort("timestamp", DESCENDING)
            .skip(skip)
            .limit(limit)
        )
        docs = await cursor.to_list(length=limit)
        return [PolicyAuditEntry.model_validate(d) for d in docs]

    async def get_by_version(
        self,
        *,
        policy_scope: str,
        project_id: Optional[str],
        version: int,
    ) -> Optional[PolicyAuditEntry]:
        doc = await self._col.find_one({
            "policy_scope": policy_scope,
            "project_id": project_id,
            "version": version,
        })
        return PolicyAuditEntry.model_validate(doc) if doc else None

    async def delete_older_than(
        self,
        *,
        policy_scope: str,
        project_id: Optional[str],
        cutoff: datetime,
    ) -> int:
        result = await self._col.delete_many({
            "policy_scope": policy_scope,
            "project_id": project_id,
            "timestamp": {"$lt": cutoff},
        })
        return result.deleted_count
