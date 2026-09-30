"""Crypto and license entries share crypto_policy_history; a document without policy_type is a crypto one."""

from datetime import datetime
from typing import Any, Literal

from pymongo import DESCENDING

from app.models.policy_audit_entry import PolicyAuditEntry, PolicyType
from app.repositories.base import BaseRepository


def _policy_type_filter(policy_type: PolicyType) -> dict[str, Any]:
    """crypto also matches docs missing the field (treated as crypto)."""
    if policy_type == "crypto":
        return {"$or": [{"policy_type": "crypto"}, {"policy_type": {"$exists": False}}]}
    return {"policy_type": policy_type}


class PolicyAuditRepository(BaseRepository[PolicyAuditEntry]):
    collection_name = "crypto_policy_history"
    model_class = PolicyAuditEntry

    async def list(
        self,
        *,
        policy_scope: Literal["system", "project"],
        project_id: str | None = None,
        policy_type: PolicyType,
        skip: int = 0,
        limit: int = 50,
    ) -> list[PolicyAuditEntry]:
        query: dict[str, Any] = {
            "policy_scope": policy_scope,
            "project_id": project_id,
            **_policy_type_filter(policy_type),
        }
        # Timestamps are stored to the millisecond and two saves can share one, so version —
        # which only ever grows within a scope — decides which of them is the later change.
        cursor = (
            self.collection.find(query)
            .sort([("timestamp", DESCENDING), ("version", DESCENDING)])
            .skip(skip)
            .limit(limit)
        )
        docs = await cursor.to_list(length=limit)
        return [PolicyAuditEntry.model_validate(d) for d in docs]

    async def get_by_version(
        self,
        *,
        policy_scope: str,
        project_id: str | None,
        version: int,
        policy_type: PolicyType,
    ) -> PolicyAuditEntry | None:
        query: dict[str, Any] = {
            "policy_scope": policy_scope,
            "project_id": project_id,
            "version": version,
            **_policy_type_filter(policy_type),
        }
        # Older histories hold duplicate versions; the newest entry is the revision a reader means.
        doc = await self.collection.find_one(query, sort=[("timestamp", DESCENDING)])
        return PolicyAuditEntry.model_validate(doc) if doc else None

    async def max_version(
        self,
        *,
        policy_scope: Literal["system", "project"],
        project_id: str | None,
        policy_type: PolicyType,
    ) -> int:
        query: dict[str, Any] = {
            "policy_scope": policy_scope,
            "project_id": project_id,
            **_policy_type_filter(policy_type),
        }
        doc = await self.collection.find_one(query, {"version": 1}, sort=[("version", DESCENDING)])
        return doc["version"] if doc else 0

    async def delete_older_than(
        self,
        *,
        policy_scope: str,
        project_id: str | None,
        cutoff: datetime,
        policy_type: PolicyType,
    ) -> int:
        query: dict[str, Any] = {
            "policy_scope": policy_scope,
            "project_id": project_id,
            "timestamp": {"$lt": cutoff},
            **_policy_type_filter(policy_type),
        }
        result = await self.collection.delete_many(query)
        return result.deleted_count

    async def delete_all_older_than(self, cutoff: datetime) -> int:
        result = await self.collection.delete_many({"timestamp": {"$lt": cutoff}})
        return result.deleted_count
