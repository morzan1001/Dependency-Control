from datetime import datetime, timezone
from typing import List, Optional
from pydantic import BaseModel, Field


class Broadcast(BaseModel):
    id: Optional[str] = Field(None, alias="_id")
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

    class Config:
        populate_by_name = True
        json_encoders = {datetime: lambda v: v.isoformat()}
