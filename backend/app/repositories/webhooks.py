"""
Webhook Repository

Centralizes all database operations for webhooks.
"""

from typing import Any, Dict, List, Optional

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.models.webhook import Webhook


class WebhookRepository:
    """Repository for webhook database operations."""

    def __init__(self, db: AsyncIOMotorDatabase):
        self.db = db
        self.collection = db.webhooks

    async def get_by_id(self, webhook_id: str) -> Optional[Webhook]:
        """Get webhook by ID."""
        data = await self.collection.find_one({"_id": webhook_id})
        if data:
            return Webhook(**data)
        return None

    async def get_raw_by_id(self, webhook_id: str) -> Optional[Dict[str, Any]]:
        """Get raw webhook document by ID."""
        return await self.collection.find_one({"_id": webhook_id})

    async def create(self, webhook: Webhook) -> Webhook:
        """Create a new webhook."""
        await self.collection.insert_one(webhook.model_dump(by_alias=True))
        return webhook

    async def update(self, webhook_id: str, update_data: Dict[str, Any]) -> Optional[Webhook]:
        """Update webhook by ID."""
        await self.collection.update_one({"_id": webhook_id}, {"$set": update_data})
        return await self.get_by_id(webhook_id)

    async def delete(self, webhook_id: str) -> bool:
        """Delete webhook by ID."""
        result = await self.collection.delete_one({"_id": webhook_id})
        return result.deleted_count > 0

    async def find_by_project(
        self,
        project_id: str,
        skip: int = 0,
        limit: int = 100,
        sort_by: str = "created_at",
        sort_order: int = -1,
    ) -> List[Webhook]:
        """Find webhooks for a project."""
        cursor = self.collection.find({"project_id": project_id}).sort(sort_by, sort_order).skip(skip).limit(limit)
        docs = await cursor.to_list(limit)
        return [Webhook(**doc) for doc in docs]

    async def find_global(
        self,
        skip: int = 0,
        limit: int = 100,
        sort_by: str = "created_at",
        sort_order: int = -1,
    ) -> List[Webhook]:
        """Find global webhooks (project_id is None)."""
        cursor = self.collection.find({"project_id": None}).sort(sort_by, sort_order).skip(skip).limit(limit)
        docs = await cursor.to_list(limit)
        return [Webhook(**doc) for doc in docs]

    async def find_many(
        self,
        query: Dict[str, Any],
        skip: int = 0,
        limit: int = 100,
        sort_by: str = "created_at",
        sort_order: int = -1,
    ) -> List[Webhook]:
        """Find multiple webhooks matching query."""
        cursor = self.collection.find(query).sort(sort_by, sort_order).skip(skip).limit(limit)
        docs = await cursor.to_list(limit)
        return [Webhook(**doc) for doc in docs]

    async def count(self, query: Optional[Dict[str, Any]] = None) -> int:
        """Count webhooks matching query."""
        return await self.collection.count_documents(query or {})

    async def count_by_project(self, project_id: str) -> int:
        """Count webhooks for a project."""
        return await self.collection.count_documents({"project_id": project_id})

    async def count_global(self) -> int:
        """Count global webhooks."""
        return await self.collection.count_documents({"project_id": None})

    async def find_active_for_project(self, project_id: str) -> List[Webhook]:
        """Find all active webhooks for a project (including global ones)."""
        query = {
            "$or": [
                {"project_id": project_id, "is_active": True},
                {"project_id": None, "is_active": True},
            ]
        }
        cursor = self.collection.find(query)
        docs = await cursor.to_list(None)
        return [Webhook(**doc) for doc in docs]

    async def find_by_event(self, project_id: Optional[str], event_type: str) -> List[Webhook]:
        """Find webhooks subscribed to a specific event type."""
        query: Dict[str, Any] = {"events": event_type, "is_active": True}

        if project_id:
            # Include project-specific and global webhooks
            query["$or"] = [{"project_id": project_id}, {"project_id": None}]
        else:
            # Only global webhooks
            query["project_id"] = None

        cursor = self.collection.find(query)
        docs = await cursor.to_list(None)
        return [Webhook(**doc) for doc in docs]
