from datetime import datetime

from app.core.constants import WebhookType
from app.models.base import CreatedAtModel
from app.models.types import MongoDocument


class Webhook(MongoDocument, CreatedAtModel):
    """Both ids None makes a webhook global."""

    project_id: str | None = None
    team_id: str | None = None
    url: str
    events: list[str]
    secret: str | None = None
    headers: dict[str, str] | None = None
    is_active: bool = True
    webhook_type: WebhookType = "generic"
    last_triggered_at: datetime | None = None
    last_failure_at: datetime | None = None

    # Circuit breaker, so a failing receiver is not hammered.
    consecutive_failures: int = 0
    circuit_breaker_until: datetime | None = None
    total_deliveries: int = 0
    total_failures: int = 0
