from datetime import datetime, timezone
from typing import List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.core.constants import TEAM_ROLE_MEMBER, TEAM_ROLES
from app.models.base import CreatedAtModel
from app.models.types import MongoDocument


class TeamMember(BaseModel):
    user_id: str
    role: str = TEAM_ROLE_MEMBER
    # Provenance of the membership (Finding 16). Defaults to "manual" so that
    # existing/manually-added members are preserved by the GitLab merge-sync —
    # only the "gitlab"-sourced subset is replaced on each sync.
    source: Literal["gitlab", "manual"] = "manual"

    @field_validator("role")
    @classmethod
    def validate_role(cls, v: str) -> str:
        if v not in TEAM_ROLES:
            raise ValueError(f"Role must be one of: {', '.join(TEAM_ROLES)}")
        return v


class Team(MongoDocument, CreatedAtModel):
    name: str
    description: Optional[str] = None
    gitlab_instance_id: Optional[str] = None
    gitlab_group_id: Optional[int] = None
    members: List[TeamMember] = Field(default_factory=list)
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    model_config = ConfigDict(arbitrary_types_allowed=True)
