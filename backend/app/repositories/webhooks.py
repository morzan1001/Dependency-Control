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
        cursor = self.collection.find(query, projection)
        if sort_by:
            cursor = cursor.sort(sort_by, sort_order)
        cursor = cursor.skip(skip).limit(limit)
        docs = await cursor.to_list(limit)
        return self._to_model_list(docs)

    async def count_by_project(self, project_id: str) -> int:
        return await self.collection.count_documents({"project_id": project_id})

    async def count_by_team(self, team_id: str) -> int:
        return await self.collection.count_documents({"team_id": team_id})

    async def count_global(self) -> int:
        """Count global webhooks (both project_id and team_id are None)."""
        return await self.collection.count_documents({"project_id": None, "team_id": None})
