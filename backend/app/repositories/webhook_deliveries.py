"""
Webhook Deliveries Repository

Manages webhook delivery audit logs.
Tracks all webhook delivery attempts (successful and failed) for compliance and debugging.
"""

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from motor.motor_asyncio import AsyncIOMotorDatabase


class WebhookDeliveriesRepository:
    """Repository for webhook delivery audit logs."""

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
        """
        Log a webhook delivery attempt.

        Args:
            webhook_id: Webhook ID
            event_type: Event type (scan_completed, vulnerability_found, etc.)
            payload_summary: Summary of the payload (not full payload to save space)
            success: Whether delivery was successful
            status_code: HTTP status code received
            error: Error message if failed
            retry_count: Number of retries attempted

        Returns:
            The ID of the created log entry
        """
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
        return log_entry["_id"]

    async def get_recent_deliveries(self, webhook_id: str, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Get recent delivery logs for a webhook.

        Args:
            webhook_id: Webhook ID
            limit: Maximum number of entries to return

        Returns:
            List of delivery log entries, sorted by timestamp (newest first)
        """
        cursor = self.collection.find({"webhook_id": webhook_id}).sort("timestamp", -1).limit(limit)

        return await cursor.to_list(length=limit)

    async def get_failure_count(self, webhook_id: str, since: Optional[datetime] = None) -> int:
        """
        Get count of failed deliveries for a webhook.

        Args:
            webhook_id: Webhook ID
            since: Optional datetime to count failures since

        Returns:
            Number of failed deliveries
        """
        query: Dict[str, Any] = {"webhook_id": webhook_id, "success": False}

        if since:
            query["timestamp"] = {"$gte": since}

        return await self.collection.count_documents(query)

    async def get_success_rate(self, webhook_id: str) -> Dict[str, Any]:
        """
        Calculate success rate for a webhook.

        Args:
            webhook_id: Webhook ID

        Returns:
            Dict with total, successful, failed counts and success_rate percentage
        """
        pipeline = [
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
        """
        Remove old delivery logs, keeping only the most recent entries.

        Args:
            webhook_id: Webhook ID
            keep_count: Number of recent logs to keep

        Returns:
            Number of logs deleted
        """
        # Find IDs to keep (most recent N)
        cursor = self.collection.find({"webhook_id": webhook_id}, {"_id": 1}).sort("timestamp", -1).limit(keep_count)

        ids_to_keep = [doc["_id"] async for doc in cursor]

        # Delete all others
        result = await self.collection.delete_many({"webhook_id": webhook_id, "_id": {"$nin": ids_to_keep}})

        return result.deleted_count

    async def delete_by_webhook(self, webhook_id: str) -> int:
        """
        Delete all delivery logs for a webhook.

        Typically called when a webhook is deleted.

        Args:
            webhook_id: Webhook ID

        Returns:
            Number of logs deleted
        """
        result = await self.collection.delete_many({"webhook_id": webhook_id})
        return result.deleted_count
