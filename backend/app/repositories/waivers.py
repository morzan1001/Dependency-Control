"""Repository for waivers."""

from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any

from motor.motor_asyncio import AsyncIOMotorDatabase
from pymongo import ReturnDocument, UpdateOne

from app.core.metrics import track_db_operation
from app.models.waiver import Waiver

_COL = "waivers"


def non_expired_waiver_filter(now: datetime | None = None) -> dict[str, Any]:
    """MongoDB clause for waivers whose expiration_date is absent, null, or in the future; mirrors is_waiver_active."""
    # An equality with null also matches a document that lacks the field.
    return {"$or": [{"expiration_date": None}, {"expiration_date": {"$gt": now or datetime.now(timezone.utc)}}]}


def _active_for_project_filter(project_id: str, include_global: bool) -> dict[str, Any]:
    project_filter = (
        {"$or": [{"project_id": project_id}, {"project_id": None}]} if include_global else {"project_id": project_id}
    )
    return {"$and": [project_filter, non_expired_waiver_filter()]}


class WaiverRepository:
    def __init__(self, db: AsyncIOMotorDatabase):
        self.db = db
        self.collection = db.waivers

    async def get_by_id(self, waiver_id: str) -> Waiver | None:
        with track_db_operation(_COL, "find_one"):
            data = await self.collection.find_one({"_id": waiver_id})
        if data:
            return Waiver(**data)
        return None

    async def get_raw_by_id(self, waiver_id: str) -> dict[str, Any] | None:
        with track_db_operation(_COL, "find_one"):
            return await self.collection.find_one({"_id": waiver_id})

    async def create(self, waiver: Waiver) -> Waiver:
        with track_db_operation(_COL, "insert_one"):
            await self.collection.insert_one(waiver.model_dump(by_alias=True))
        return waiver

    async def update(self, waiver_id: str, update_data: dict[str, Any]) -> Waiver | None:
        with track_db_operation(_COL, "find_one_and_update"):
            data = await self.collection.find_one_and_update(
                {"_id": waiver_id}, {"$set": update_data}, return_document=ReturnDocument.AFTER
            )
        return Waiver(**data) if data else None

    async def set_fields_many(self, fields_by_id: Mapping[str, dict[str, Any]]) -> None:
        if not fields_by_id:
            return
        with track_db_operation(_COL, "bulk_write"):
            await self.collection.bulk_write(
                [UpdateOne({"_id": wid}, {"$set": fields}) for wid, fields in fields_by_id.items()],
                ordered=False,
            )

    async def delete(self, waiver_id: str) -> bool:
        with track_db_operation(_COL, "delete_one"):
            result = await self.collection.delete_one({"_id": waiver_id})
        return result.deleted_count > 0

    async def delete_many(self, query: dict[str, Any]) -> int:
        with track_db_operation(_COL, "delete_many"):
            result = await self.collection.delete_many(query)
        return result.deleted_count

    async def find_by_project(
        self,
        project_id: str,
        skip: int = 0,
        limit: int = 1000,
    ) -> list[dict[str, Any]]:
        """Returns raw dicts (not Waiver models) to avoid model overhead in bulk listings."""
        with track_db_operation(_COL, "find"):
            cursor = self.collection.find({"project_id": project_id}).skip(skip).limit(limit)
            return await cursor.to_list(limit)

    async def find_many(
        self,
        query: dict[str, Any],
        skip: int = 0,
        limit: int = 1000,
        sort_by: str = "created_at",
        sort_order: int = -1,
    ) -> list[dict[str, Any]]:
        """Returns raw dicts (not Waiver models) to avoid model overhead in bulk listings."""
        with track_db_operation(_COL, "find"):
            cursor = self.collection.find(query).sort(sort_by, sort_order).skip(skip).limit(limit)
            return await cursor.to_list(limit)

    async def count(self, query: dict[str, Any] | None = None) -> int:
        with track_db_operation(_COL, "count"):
            return await self.collection.count_documents(query or {})

    async def find_active_for_project(self, project_id: str, include_global: bool = True) -> list[Waiver]:
        """Active (non-expired) waivers for a project; include_global also matches global waivers (project_id=None)."""
        with track_db_operation(_COL, "find"):
            cursor = self.collection.find(_active_for_project_filter(project_id, include_global))
            docs = await cursor.to_list(None)
        return [Waiver(**doc) for doc in docs]

    async def has_active_for_project(self, project_id: str) -> bool:
        """Whether the project, or a global waiver, has an active waiver; stops at the first one found."""
        with track_db_operation(_COL, "count"):
            return await self.collection.count_documents(_active_for_project_filter(project_id, True), limit=1) > 0

    async def find_active_global(self) -> list[Waiver]:
        """Active (non-expired) waivers that apply to every project (project_id=None)."""
        query: dict[str, Any] = {"$and": [{"project_id": None}, non_expired_waiver_filter()]}

        with track_db_operation(_COL, "find"):
            cursor = self.collection.find(query)
            docs = await cursor.to_list(None)
        return [Waiver(**doc) for doc in docs]
