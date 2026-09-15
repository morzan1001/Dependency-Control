"""Audit log of webhook delivery attempts."""

import uuid
from datetime import datetime, timezone
from typing import Any

from motor.motor_asyncio import AsyncIOMotorDatabase


class WebhookDeliveriesRepository:
    def __init__(self, db: AsyncIOMotorDatabase):
        self.db = db
        self.collection = db.webhook_deliveries

    async def log_delivery(
        self,
        webhook_id: str,
        event_type: str,
        payload_summary: dict[str, Any],
        success: bool,
        status_code: int | None = None,
        error: str | None = None,
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
