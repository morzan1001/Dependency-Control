import uuid
from datetime import datetime, timezone
from typing import List, Optional

from pydantic import BaseModel, Field


class TeamMember(BaseModel):
    user_id: str
    role: str = "member"  # "owner", "admin", "member"


class Team(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()), alias="_id")
    name: str
    description: Optional[str] = None
    members: List[TeamMember] = []
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    class Config:
        populate_by_name = True
        arbitrary_types_allowed = True
