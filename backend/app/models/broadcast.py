import uuid
from datetime import datetime, timezone
from typing import List, Optional

from pydantic import BaseModel, ConfigDict, Field

from app.models.types import PyObjectId


class Broadcast(BaseModel):
    id: PyObjectId = Field(
        default_factory=lambda: str(uuid.uuid4()),
        validation_alias="_id",
        serialization_alias="_id",
    )
    type: str  # 'general' or 'advisory'
    target_type: str  # 'global', 'teams', 'advisory'
    subject: str
    message: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    created_by: str  # user_id

    # Stats
    recipient_count: int = 0
    project_count: int = 0

    # Configuration
    packages: Optional[List[dict]] = None
    channels: Optional[List[str]] = None
    teams: Optional[List[str]] = None

    model_config = ConfigDict(populate_by_name=True)
