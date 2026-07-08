"""Audit log of webhook delivery attempts."""

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from motor.motor_asyncio import AsyncIOMotorDatabase


class WebhookDeliveriesRepository:
    def __init__(self, db: AsyncIOMotorDatabase):
        self.db = db
        self.collection = db.webhook_deliveries

    async def log_delivery(
        self,
        webhook_id: str,
        event_type: str,
        payload_summary: Dict[str, Any],
        success: bool,
        status_code: Optional[int] = None,
        error: Optional[str] = None,
        retry_count: int = 0,
    ) -> str:
        log_entry = {
            "_id": str(uuid.uuid4()),
            "webhook_id": webhook_id,
            "event_type": event_type,
            "success": success,
            "status_code": status_code,
            "error": error,
            "retry_count": retry_count,
            "timestamp": datetime.now(timezone.utc),
            "payload_summary": payload_summary,
        }

        await self.collection.insert_one(log_entry)
        return str(log_entry["_id"])

    async def get_recent_deliveries(self, webhook_id: str, limit: int = 100) -> List[Dict[str, Any]]:
        cursor = self.collection.find({"webhook_id": webhook_id}).sort("timestamp", -1).limit(limit)
        return await cursor.to_list(length=limit)

    async def get_failure_count(self, webhook_id: str, since: Optional[datetime] = None) -> int:
        query: Dict[str, Any] = {"webhook_id": webhook_id, "success": False}

        if since:
            query["timestamp"] = {"$gte": since}

        return await self.collection.count_documents(query)

    async def get_success_rate(self, webhook_id: str) -> Dict[str, Any]:
        """Returns total, successful, failed counts and success_rate percentage."""
        pipeline: List[Dict[str, Any]] = [
            {"$match": {"webhook_id": webhook_id}},
            {
                "$group": {
                    "_id": None,
                    "total": {"$sum": 1},
                    "successful": {"$sum": {"$cond": [{"$eq": ["$success", True]}, 1, 0]}},
                    "failed": {"$sum": {"$cond": [{"$eq": ["$success", False]}, 1, 0]}},
                }
            },
        ]

        result = await self.collection.aggregate(pipeline).to_list(length=1)

        if not result:
            return {"total": 0, "successful": 0, "failed": 0, "success_rate": 0.0}

        stats = result[0]
        total = stats["total"]
        successful = stats["successful"]

        return {
            "total": total,
            "successful": successful,
            "failed": stats["failed"],
            "success_rate": (successful / total * 100) if total > 0 else 0.0,
        }

    async def cleanup_old_logs(self, webhook_id: str, keep_count: int = 1000) -> int:
        """Keep only the most recent keep_count logs for the webhook."""
        cursor = self.collection.find({"webhook_id": webhook_id}, {"_id": 1}).sort("timestamp", -1).limit(keep_count)
        ids_to_keep = [doc["_id"] async for doc in cursor]
        result = await self.collection.delete_many({"webhook_id": webhook_id, "_id": {"$nin": ids_to_keep}})
        return result.deleted_count

    async def delete_by_webhook(self, webhook_id: str) -> int:
        result = await self.collection.delete_many({"webhook_id": webhook_id})
        return result.deleted_count
