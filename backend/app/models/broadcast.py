from app.models.base import CreatedAtModel
from app.models.types import MongoDocument


class Broadcast(MongoDocument, CreatedAtModel):
    type: str
    target_type: str
    subject: str
    message: str
    created_by: str  # user_id

    recipient_count: int = 0
    project_count: int = 0

    packages: list[dict] | None = None
    channels: list[str] | None = None
    teams: list[str] | None = None
