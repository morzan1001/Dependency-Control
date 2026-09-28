"""Repository for waivers."""

from datetime import datetime, timezone
from typing import Any

from app.models.waiver import Waiver
from app.repositories.base import BaseRepository


def _non_expired_filter(now: datetime | None = None) -> dict[str, Any]:
    """Return a MongoDB $or clause matching waivers whose expiration_date is absent, null, or in the future."""
    ts = now or datetime.now(timezone.utc)
    return {
        "$or": [{"expiration_date": {"$exists": False}}, {"expiration_date": None}, {"expiration_date": {"$gt": ts}}]
    }


class WaiverRepository(BaseRepository[Waiver]):
    collection_name = "waivers"
    model_class = Waiver

    async def find_many(
        self,
        query: dict[str, Any],
        skip: int = 0,
        limit: int = 100,
        sort_by: str | None = "created_at",
        sort_order: int = -1,
    ) -> list[Waiver]:
        if limit <= 0:
            return []
        # The listing pages on a user-chosen column many waivers share; _id keeps the pages disjoint.
        sort = [(sort_by, sort_order), ("_id", 1)] if sort_by and sort_by != "_id" else [("_id", sort_order)]
        cursor = self.collection.find(query).sort(sort).skip(skip).limit(limit)
        return self._to_model_list(await cursor.to_list(limit))

    async def find_active_for_project(self, project_id: str, include_global: bool = True) -> list[Waiver]:
        """Active (non-expired) waivers for a project; include_global also matches global waivers (project_id=None)."""
        now = datetime.now(timezone.utc)

        project_filter = (
            {"$or": [{"project_id": project_id}, {"project_id": None}]}
            if include_global
            else {"project_id": project_id}
        )
        query: dict[str, Any] = {"$and": [project_filter, _non_expired_filter(now=now)]}

        cursor = self.collection.find(query)
        docs = await cursor.to_list(None)
        return [Waiver(**doc) for doc in docs]

    async def find_active_global(self) -> list[Waiver]:
        """Active (non-expired) waivers that apply to every project (project_id=None)."""
        query: dict[str, Any] = {"$and": [{"project_id": None}, _non_expired_filter(now=datetime.now(timezone.utc))]}

        cursor = self.collection.find(query)
        docs = await cursor.to_list(None)
        return [Waiver(**doc) for doc in docs]
