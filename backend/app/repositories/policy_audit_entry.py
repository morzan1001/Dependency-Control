"""PolicyAuditRepository — MongoDB access for `crypto_policy_history`.

Entries carry a ``policy_type`` discriminator (default ``"crypto"``) so
crypto and license policies share one collection. Queries without an
explicit ``policy_type`` default to ``crypto`` so entries written before
the discriminator existed still match.
"""

from datetime import datetime
from typing import Any, Dict, List, Literal, Optional

from motor.motor_asyncio import AsyncIOMotorDatabase
from pymongo import DESCENDING

from app.models.policy_audit_entry import PolicyAuditEntry

PolicyType = Literal["crypto", "license"]


def _policy_type_filter(policy_type: PolicyType) -> Dict[str, Any]:
    """For ``"crypto"`` we also match documents missing the field — they
    pre-date the discriminator."""
    if policy_type == "crypto":
        return {"$or": [{"policy_type": "crypto"}, {"policy_type": {"$exists": False}}]}
    return {"policy_type": policy_type}


class PolicyAuditRepository:
    COLLECTION = "crypto_policy_history"

    def __init__(self, db: AsyncIOMotorDatabase):
        self._col = db[self.COLLECTION]

    async def ensure_indexes(self) -> None:
        # (policy_type, policy_scope, project_id, version) — uniqueness so
        # crypto and license policies may both have version 1 for one project.
        await self._col.create_index([("policy_type", 1), ("policy_scope", 1), ("project_id", 1), ("version", -1)])
        # Index without policy_type for queries that don't filter on it.
        await self._col.create_index([("policy_scope", 1), ("project_id", 1), ("version", -1)])
        await self._col.create_index([("timestamp", -1)])
        await self._col.create_index([("actor_user_id", 1), ("timestamp", -1)])

    async def insert(self, entry: PolicyAuditEntry) -> None:
        await self._col.insert_one(entry.model_dump(by_alias=True))

    async def list(
        self,
        *,
        policy_scope: Literal["system", "project"],
        project_id: Optional[str] = None,
        policy_type: PolicyType = "crypto",
        skip: int = 0,
        limit: int = 50,
    ) -> List[PolicyAuditEntry]:
        query: Dict[str, Any] = {
            "policy_scope": policy_scope,
            "project_id": project_id,
            **_policy_type_filter(policy_type),
        }
        cursor = self._col.find(query).sort("timestamp", DESCENDING).skip(skip).limit(limit)
        docs = await cursor.to_list(length=limit)
        return [PolicyAuditEntry.model_validate(d) for d in docs]

    async def get_by_version(
        self,
        *,
        policy_scope: str,
        project_id: Optional[str],
        version: int,
        policy_type: PolicyType = "crypto",
    ) -> Optional[PolicyAuditEntry]:
        query: Dict[str, Any] = {
            "policy_scope": policy_scope,
            "project_id": project_id,
            "version": version,
            **_policy_type_filter(policy_type),
        }
        doc = await self._col.find_one(query)
        return PolicyAuditEntry.model_validate(doc) if doc else None

    async def count(
        self,
        *,
        policy_scope: Literal["system", "project"],
        project_id: Optional[str] = None,
        policy_type: PolicyType = "crypto",
    ) -> int:
        query: Dict[str, Any] = {
            "policy_scope": policy_scope,
            "project_id": project_id,
            **_policy_type_filter(policy_type),
        }
        return await self._col.count_documents(query)

    async def delete_older_than(
        self,
        *,
        policy_scope: str,
        project_id: Optional[str],
        cutoff: datetime,
        policy_type: PolicyType = "crypto",
    ) -> int:
        query: Dict[str, Any] = {
            "policy_scope": policy_scope,
            "project_id": project_id,
            "timestamp": {"$lt": cutoff},
            **_policy_type_filter(policy_type),
        }
        result = await self._col.delete_many(query)
        return result.deleted_count
