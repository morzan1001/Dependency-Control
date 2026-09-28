"""Repository for webhooks."""

from typing import Any

from app.models.webhook import Webhook
from app.repositories.base import BaseRepository

GLOBAL_WEBHOOK_SCOPE: dict[str, Any] = {"project_id": None, "team_id": None}


class WebhookRepository(BaseRepository[Webhook]):
    collection_name = "webhooks"
    model_class = Webhook

    async def list_scope(self, scope: dict[str, Any], skip: int, limit: int) -> list[Webhook]:
        """One page of a project's, a team's or the global webhooks, newest first."""
        return await self.find_many(scope, skip=skip, limit=limit, sort_by="created_at", sort_order=-1)
