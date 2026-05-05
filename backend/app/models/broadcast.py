import uuid
from typing import List, Optional

from pydantic import ConfigDict, Field

from app.models.base import CreatedAtModel
from app.models.types import PyObjectId


class Broadcast(CreatedAtModel):
    id: PyObjectId = Field(
        default_factory=lambda: str(uuid.uuid4()),
        validation_alias="_id",
        serialization_alias="_id",
    )
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

    model_config = ConfigDict(populate_by_name=True)
