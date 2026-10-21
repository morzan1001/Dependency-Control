"""Crypto and license entries share crypto_policy_history, told apart by policy_type."""

from datetime import datetime
from typing import Any, Literal

from pymongo import DESCENDING

from app.models.policy_audit_entry import PolicyAuditEntry, PolicyType
from app.repositories.base import BaseRepository

# Two saves can share a millisecond timestamp, so version, which only grows within a scope, orders them.
NEWEST_ENTRY_FIRST = [("timestamp", DESCENDING), ("version", DESCENDING)]


def history_query(*, policy_scope: str, project_id: str | None, policy_type: PolicyType) -> dict[str, Any]:
    return {"policy_scope": policy_scope, "project_id": project_id, "policy_type": policy_type}


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
        query = history_query(policy_scope=policy_scope, project_id=project_id, policy_type=policy_type)
        cursor = self.collection.find(query).sort(NEWEST_ENTRY_FIRST).skip(skip).limit(limit)
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
        query = {
            **history_query(policy_scope=policy_scope, project_id=project_id, policy_type=policy_type),
            "version": version,
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
        query = history_query(policy_scope=policy_scope, project_id=project_id, policy_type=policy_type)
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
        query = {
            **history_query(policy_scope=policy_scope, project_id=project_id, policy_type=policy_type),
            "timestamp": {"$lt": cutoff},
        }
        result = await self.collection.delete_many(query)
        return result.deleted_count

    async def delete_all_older_than(self, cutoff: datetime) -> int:
        result = await self.collection.delete_many({"timestamp": {"$lt": cutoff}})
        return result.deleted_count
