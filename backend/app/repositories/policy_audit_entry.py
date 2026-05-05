"""PolicyAuditRepository — MongoDB access for `crypto_policy_history`.

Entries carry a ``policy_type`` discriminator (default ``"crypto"``) so
crypto and license policies share one collection. Queries without an
explicit ``policy_type`` default to ``crypto`` so entries written before
the discriminator existed still match.
"""

from datetime import datetime
from typing import Any, Dict, List, Literal, Optional

from pymongo import DESCENDING

from app.core.metrics import track_db_operation
from app.models.policy_audit_entry import PolicyAuditEntry
from app.repositories.base import BaseRepository

PolicyType = Literal["crypto", "license"]


def _policy_type_filter(policy_type: PolicyType) -> Dict[str, Any]:
    """For ``"crypto"`` we also match documents missing the field — they
    pre-date the discriminator."""
    if policy_type == "crypto":
        return {"$or": [{"policy_type": "crypto"}, {"policy_type": {"$exists": False}}]}
    return {"policy_type": policy_type}


class PolicyAuditRepository(BaseRepository[PolicyAuditEntry]):
    collection_name = "crypto_policy_history"
    model_class = PolicyAuditEntry

    async def insert(self, entry: PolicyAuditEntry) -> None:
        with track_db_operation(self.collection_name, "insert_one"):
            await self.collection.insert_one(entry.model_dump(by_alias=True))

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
        with track_db_operation(self.collection_name, "find"):
            cursor = self.collection.find(query).sort("timestamp", DESCENDING).skip(skip).limit(limit)
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
        with track_db_operation(self.collection_name, "find_one"):
            doc = await self.collection.find_one(query)
        return PolicyAuditEntry.model_validate(doc) if doc else None

    async def count_entries(
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
        with track_db_operation(self.collection_name, "count"):
            return await self.collection.count_documents(query)

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
        with track_db_operation(self.collection_name, "delete_many"):
            result = await self.collection.delete_many(query)
        return result.deleted_count
