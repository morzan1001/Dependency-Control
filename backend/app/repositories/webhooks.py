"""Repository for webhooks."""

import logging
from collections.abc import Sequence
from datetime import datetime
from typing import Any

from app.models.webhook import Webhook
from app.repositories.base import BaseRepository, and_filters

logger = logging.getLogger(__name__)

GLOBAL_WEBHOOK_SCOPE: dict[str, Any] = {"project_id": None, "team_id": None}
DELIVERY_FIELDS = ("url", "webhook_type", "secret", "headers")


def _circuit_closed(now: datetime) -> dict[str, Any]:
    return {"$or": [{"circuit_breaker_until": None}, {"circuit_breaker_until": {"$lte": now}}]}


def _delivered_with(webhook: Webhook) -> dict[str, Any]:
    """Matches only while the webhook still has the settings this delivery went out with."""
    sent_with = {field: getattr(webhook, field) for field in DELIVERY_FIELDS}
    # Webhooks stored before the type field existed lack it and read as generic.
    return {"_id": webhook.id, **sent_with, "webhook_type": {"$in": [webhook.webhook_type, None]}}


class WebhookRepository(BaseRepository[Webhook]):
    collection_name = "webhooks"
    model_class = Webhook

    async def list_scope(self, scope: dict[str, Any], skip: int, limit: int) -> list[Webhook]:
        """One page of a project's, a team's or the global webhooks, newest first."""
        return await self.find_many(scope, skip=skip, limit=limit, sort_by="created_at", sort_order=-1)

    async def find_deliverable(
        self, event_type: str, now: datetime, project_id: str | None, team_ids: Sequence[str]
    ) -> list[Webhook]:
        """Active subscribers to the event outside a circuit-breaker cool-down, in the project, team or global scope."""
        scopes: list[dict[str, Any]] = [GLOBAL_WEBHOOK_SCOPE]
        if project_id:
            scopes.append({"project_id": project_id})
        if team_ids:
            scopes.append({"team_id": {"$in": list(team_ids)}})
        query = and_filters({"is_active": True, "events": event_type, "$or": scopes}, _circuit_closed(now))
        webhooks: list[Webhook] = []
        async for doc in self.collection.find(query):
            try:
                webhooks.append(Webhook(**doc))
            except Exception:
                logger.exception("Skipping unreadable webhook %s", doc.get("_id"))
        return webhooks

    async def record_success(self, webhook: Webhook, now: datetime) -> None:
        await self.collection.update_one(
            _delivered_with(webhook),
            {
                "$set": {"last_triggered_at": now, "consecutive_failures": 0, "circuit_breaker_until": None},
                "$inc": {"total_deliveries": 1},
            },
        )

    async def record_failure(
        self, webhook: Webhook, now: datetime, threshold: int, open_until: datetime
    ) -> dict[str, Any] | None:
        """Count the failure; returns the document only from the failure that opened the circuit."""
        await self.collection.update_one(
            _delivered_with(webhook),
            {"$set": {"last_failure_at": now}, "$inc": {"consecutive_failures": 1, "total_failures": 1}},
        )
        opened: dict[str, Any] | None = await self.collection.find_one_and_update(
            {**_delivered_with(webhook), "consecutive_failures": {"$gte": threshold}, **_circuit_closed(now)},
            {"$set": {"circuit_breaker_until": open_until}},
            return_document=True,
        )
        return opened
