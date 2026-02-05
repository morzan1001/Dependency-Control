import uuid
from datetime import datetime, timezone
from typing import List, Optional

from pydantic import BaseModel, Field

from app.core.constants import TEAM_ROLE_MEMBER
from app.models.types import PyObjectId


class TeamMember(BaseModel):
    user_id: str
    role: str = TEAM_ROLE_MEMBER  # One of TEAM_ROLES


class Team(BaseModel):
    # validation_alias="_id": accepts _id from MongoDB
    # serialization_alias="_id": model_dump(by_alias=True) outputs _id for MongoDB
    id: PyObjectId = Field(
        default_factory=lambda: str(uuid.uuid4()),
        validation_alias="_id",
        serialization_alias="_id",
    )
    name: str
    description: Optional[str] = None
    members: List[TeamMember] = []
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    class Config:
        populate_by_name = True
        arbitrary_types_allowed = True
