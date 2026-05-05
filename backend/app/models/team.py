import uuid
from typing import List, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.core.constants import TEAM_ROLE_MEMBER, TEAM_ROLES
from app.models.base import TimestampedModel
from app.models.types import PyObjectId


class TeamMember(BaseModel):
    user_id: str
    role: str = TEAM_ROLE_MEMBER

    @field_validator("role")
    @classmethod
    def validate_role(cls, v: str) -> str:
        if v not in TEAM_ROLES:
            raise ValueError(f"Role must be one of: {', '.join(TEAM_ROLES)}")
        return v


class Team(TimestampedModel):
    id: PyObjectId = Field(
        default_factory=lambda: str(uuid.uuid4()),
        validation_alias="_id",
        serialization_alias="_id",
    )
    name: str
    description: Optional[str] = None
    gitlab_instance_id: Optional[str] = None
    gitlab_group_id: Optional[int] = None
    members: List[TeamMember] = Field(default_factory=list)

    model_config = ConfigDict(populate_by_name=True, arbitrary_types_allowed=True)
