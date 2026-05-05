"""Repository for webhooks."""

from typing import Any, Dict, List, Optional

from app.models.webhook import Webhook
from app.repositories.base import BaseRepository


class WebhookRepository(BaseRepository[Webhook]):
    collection_name = "webhooks"
    model_class = Webhook

    async def find_by_project(
        self,
        project_id: str,
        skip: int = 0,
        limit: int = 100,
        sort_by: str = "created_at",
        sort_order: int = -1,
    ) -> List[Webhook]:
        cursor = self.collection.find({"project_id": project_id}).sort(sort_by, sort_order).skip(skip).limit(limit)
        docs = await cursor.to_list(limit)
        return self._to_model_list(docs)

    async def find_by_team(
        self,
        team_id: str,
        skip: int = 0,
        limit: int = 100,
        sort_by: str = "created_at",
        sort_order: int = -1,
    ) -> List[Webhook]:
        cursor = self.collection.find({"team_id": team_id}).sort(sort_by, sort_order).skip(skip).limit(limit)
        docs = await cursor.to_list(limit)
        return self._to_model_list(docs)

    async def find_global(
        self,
        skip: int = 0,
        limit: int = 100,
        sort_by: str = "created_at",
        sort_order: int = -1,
    ) -> List[Webhook]:
        """Find global webhooks (both project_id and team_id are None)."""
        cursor = (
            self.collection.find({"project_id": None, "team_id": None})
            .sort(sort_by, sort_order)
            .skip(skip)
            .limit(limit)
        )
        docs = await cursor.to_list(limit)
        return self._to_model_list(docs)

    async def find_many(
        self,
        query: Dict[str, Any],
        skip: int = 0,
        limit: int = 100,
        sort_by: Optional[str] = "created_at",
        sort_order: int = -1,
        projection: Optional[Dict[str, int]] = None,
    ) -> List[Webhook]:
        cursor = self.collection.find(query, projection).sort(sort_by, sort_order).skip(skip).limit(limit)
        docs = await cursor.to_list(limit)
        return self._to_model_list(docs)

    async def count_by_project(self, project_id: str) -> int:
        return await self.collection.count_documents({"project_id": project_id})

    async def count_by_team(self, team_id: str) -> int:
        return await self.collection.count_documents({"team_id": team_id})

    async def count_global(self) -> int:
        """Count global webhooks (both project_id and team_id are None)."""
        return await self.collection.count_documents({"project_id": None, "team_id": None})

    async def find_active_for_project(self, project_id: str, team_id: Optional[str] = None) -> List[Webhook]:
        """Find all active webhooks for a project (including team and global ones)."""
        or_conditions: List[Dict[str, Any]] = [
            {"project_id": project_id, "is_active": True},
            {"project_id": None, "team_id": None, "is_active": True},
        ]
        if team_id:
            or_conditions.append({"team_id": team_id, "is_active": True})
        cursor = self.collection.find({"$or": or_conditions})
        docs = await cursor.to_list(200)
        return self._to_model_list(docs)

    async def find_by_event(
        self, project_id: Optional[str], event_type: str, team_id: Optional[str] = None
    ) -> List[Webhook]:
        query: Dict[str, Any] = {"events": event_type, "is_active": True}

        if project_id:
            or_conditions: List[Dict[str, Any]] = [
                {"project_id": project_id},
                {"project_id": None, "team_id": None},
            ]
            if team_id:
                or_conditions.append({"team_id": team_id})
            query["$or"] = or_conditions
        else:
            query["project_id"] = None
            query["team_id"] = None

        cursor = self.collection.find(query)
        docs = await cursor.to_list(200)
        return self._to_model_list(docs)
