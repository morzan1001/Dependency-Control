from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.core.constants import TEAM_ROLE_MEMBER, TEAM_ROLES
from app.models.base import CreatedAtModel
from app.models.types import MongoDocument


class TeamMember(BaseModel):
    user_id: str
    role: str = TEAM_ROLE_MEMBER
    # Defaults to "manual" so manually-added members survive merge-sync; only the
    # provider-sourced subset is replaced on each sync.
    source: Literal["gitlab", "github", "manual"] = "manual"

    @field_validator("role")
    @classmethod
    def validate_role(cls, v: str) -> str:
        if v not in TEAM_ROLES:
            raise ValueError(f"Role must be one of: {', '.join(TEAM_ROLES)}")
        return v


class Team(MongoDocument, CreatedAtModel):
    name: str
    description: str | None = None
    gitlab_instance_id: str | None = None
    gitlab_group_id: int | None = None
    github_instance_id: str | None = None
    github_org: str | None = None
    # The numeric id identifies the team; slugs are renameable.
    github_team_id: int | None = None
    github_team_slug: str | None = None
    members: list[TeamMember] = Field(default_factory=list)
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    model_config = ConfigDict(arbitrary_types_allowed=True)
