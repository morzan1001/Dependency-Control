from typing import List, Optional

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
    packages: Optional[List[dict]] = None
    channels: Optional[List[str]] = None
    teams: Optional[List[str]] = None
