from datetime import datetime, timezone
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, computed_field, field_validator

from app.core.constants import TEAM_ROLE_MEMBER, TEAM_ROLES, team_binding_key
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


class _ProviderBinding(BaseModel):
    provider: str
    instance_id: str
    # The numeric id identifies the group or team; paths and slugs move when one is renamed.
    external_id: int

    @computed_field  # type: ignore[prop-decorator]
    @property
    def key(self) -> str:
        """Stored, and the unique index is on it. Derived rather than accepted from the caller so
        it cannot name a binding other than the one it sits in."""
        return team_binding_key(self.provider, self.instance_id, self.external_id)


class GitHubTeamBinding(_ProviderBinding):
    provider: Literal["github"] = "github"
    org: str
    slug: str | None = None


class GitLabGroupBinding(_ProviderBinding):
    provider: Literal["gitlab"] = "gitlab"
    path: str | None = None


TeamBinding = Annotated[GitHubTeamBinding | GitLabGroupBinding, Field(discriminator="provider")]


def binding_of(team: dict[str, Any], instance_id: str) -> dict[str, Any] | None:
    """The team's binding for one instance, as stored. At most one exists per (team, instance)."""
    for binding in team.get("bindings") or []:
        if binding.get("instance_id") == instance_id:
            return dict(binding)
    return None


class Team(MongoDocument, CreatedAtModel):
    name: str
    description: str | None = None
    # One entry per instance the team is bound to, of either provider, in any number.
    bindings: list[TeamBinding] = Field(default_factory=list)
    members: list[TeamMember] = Field(default_factory=list)
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    model_config = ConfigDict(arbitrary_types_allowed=True)
