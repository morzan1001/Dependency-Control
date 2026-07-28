from app.models.base import CreatedAtModel
from app.models.types import MongoDocument


class Broadcast(MongoDocument, CreatedAtModel):
    type: str  # 'general' or 'advisory'
    target_type: str  # 'global', 'teams', 'advisory'
    subject: str
    message: str
    created_by: str  # user_id

    # Stats
    recipient_count: int = 0
    project_count: int = 0

    # Configuration
    packages: list[dict] | None = None
    channels: list[str] | None = None
    teams: list[str] | None = None
