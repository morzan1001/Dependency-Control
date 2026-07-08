"""
Webhook model for MongoDB storage.
"""

from datetime import datetime
from typing import Dict, List, Literal, Optional

from pydantic import ConfigDict, field_validator

from app.models.base import CreatedAtModel
from app.models.types import MongoDocument
from app.services.webhooks.validation import (
    validate_webhook_events,
    validate_webhook_url,
)


class Webhook(MongoDocument, CreatedAtModel):
    """Webhook configuration for event notifications, scoped to a project, a team, or globally (both IDs None)."""

    project_id: Optional[str] = None
    team_id: Optional[str] = None
    url: str
    events: List[str]
    secret: Optional[str] = None
    headers: Optional[Dict[str, str]] = None
    is_active: bool = True
    webhook_type: Literal["generic", "teams"] = "generic"
    last_triggered_at: Optional[datetime] = None
    last_failure_at: Optional[datetime] = None

    # Circuit Breaker fields (prevent hammering failing webhooks)
    consecutive_failures: int = 0
    circuit_breaker_until: Optional[datetime] = None
    total_deliveries: int = 0
    total_failures: int = 0

    @field_validator("events")
    @classmethod
    def _validate_events(cls, v: List[str]) -> List[str]:
        return validate_webhook_events(v, allow_empty=False)

    @field_validator("url")
    @classmethod
    def _validate_url(cls, v: str) -> str:
        return validate_webhook_url(v)

    model_config = ConfigDict(arbitrary_types_allowed=True)
