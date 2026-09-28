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

    async def find_active_for_project(self, project_id: str, include_global: bool = True) -> list[Waiver]:
        """Active (non-expired) waivers for a project; include_global also matches global waivers (project_id=None)."""
        now = datetime.now(timezone.utc)

        project_filter = (
            {"$or": [{"project_id": project_id}, {"project_id": None}]}
            if include_global
            else {"project_id": project_id}
        )
        query: dict[str, Any] = {"$and": [project_filter, _non_expired_filter(now=now)]}
        return self._to_model_list(await self.collection.find(query).to_list(None))

    async def find_active_global(self) -> list[Waiver]:
        """Active (non-expired) waivers that apply to every project (project_id=None)."""
        query: dict[str, Any] = {"$and": [{"project_id": None}, _non_expired_filter(now=datetime.now(timezone.utc))]}
        return self._to_model_list(await self.collection.find(query).to_list(None))
