"""Repository for waivers."""

from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any

from pymongo import ReturnDocument, UpdateOne

from app.models.waiver import Waiver
from app.repositories.base import BaseRepository


def non_expired_waiver_filter(now: datetime) -> dict[str, Any]:
    """MongoDB clause for waivers whose expiration_date is absent, null, or in the future; mirrors is_waiver_active."""
    # An equality with null also matches a document that lacks the field.
    return {"$or": [{"expiration_date": None}, {"expiration_date": {"$gt": now}}]}


def _active_for_project_filter(project_id: str) -> dict[str, Any]:
    """The project's own and the global waivers that have not expired."""
    project_or_global = {"$or": [{"project_id": project_id}, {"project_id": None}]}
    return {"$and": [project_or_global, non_expired_waiver_filter(datetime.now(timezone.utc))]}


class WaiverRepository(BaseRepository[Waiver]):
    collection_name = "waivers"
    model_class = Waiver

    async def update(self, waiver_id: str, update_data: dict[str, Any]) -> Waiver | None:
        data = await self.collection.find_one_and_update(
            {"_id": waiver_id}, {"$set": update_data}, return_document=ReturnDocument.AFTER
        )
        return self._to_model(data)

    async def set_fields_many(self, fields_by_id: Mapping[str, dict[str, Any]]) -> None:
        if not fields_by_id:
            return
        await self.collection.bulk_write(
            [UpdateOne({"_id": wid}, {"$set": fields}) for wid, fields in fields_by_id.items()],
            ordered=False,
        )

    async def find_active_for_project(self, project_id: str) -> list[Waiver]:
        """Active (non-expired) waivers that apply to a project: its own and the global ones (project_id=None)."""
        return self._to_model_list(await self.collection.find(_active_for_project_filter(project_id)).to_list(None))

    async def find_active_global(self) -> list[Waiver]:
        """Active (non-expired) waivers that apply to every project (project_id=None)."""
        query: dict[str, Any] = {"$and": [{"project_id": None}, non_expired_waiver_filter(datetime.now(timezone.utc))]}
        return self._to_model_list(await self.collection.find(query).to_list(None))
