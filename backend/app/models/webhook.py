"""
Webhook model for MongoDB storage.
"""

from datetime import datetime
from typing import Literal

from pydantic import ConfigDict, field_validator

from app.models.base import CreatedAtModel
from app.models.types import MongoDocument
from app.services.webhooks.validation import (
    validate_webhook_events,
    validate_webhook_url,
)


class Webhook(MongoDocument, CreatedAtModel):
    """Webhook configuration for event notifications, scoped to a project, a team, or globally (both IDs None)."""

    project_id: str | None = None
    team_id: str | None = None
    url: str
    events: list[str]
    secret: str | None = None
    headers: dict[str, str] | None = None
    is_active: bool = True
    webhook_type: Literal["generic", "teams"] = "generic"
    last_triggered_at: datetime | None = None
    last_failure_at: datetime | None = None

    # Circuit Breaker fields (prevent hammering failing webhooks)
    consecutive_failures: int = 0
    circuit_breaker_until: datetime | None = None
    total_deliveries: int = 0
    total_failures: int = 0

    @field_validator("events")
    @classmethod
    def _validate_events(cls, v: list[str]) -> list[str]:
        return validate_webhook_events(v, allow_empty=False)

    @field_validator("url")
    @classmethod
    def _validate_url(cls, v: str) -> str:
        return validate_webhook_url(v)

    model_config = ConfigDict(arbitrary_types_allowed=True)
