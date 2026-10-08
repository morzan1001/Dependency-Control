from datetime import datetime, timezone
from typing import Annotated, Any, Literal, NamedTuple

from pydantic import BaseModel, ConfigDict, Field, computed_field

from app.core.constants import TEAM_ROLE_MEMBER, TEAM_SOURCE_MANUAL, TeamRole, team_binding_key
from app.models.base import CreatedAtModel
from app.models.types import MongoDocument


class TeamMember(BaseModel):
    user_id: str
    role: TeamRole = TEAM_ROLE_MEMBER
    # "manual" or the "<provider>:<instance id>" of the sync that may replace it; unconstrained, as an
    # unmigrated value rejected here would fail every read of the team instead of staying in place.
    source: str = TEAM_SOURCE_MANUAL


class _ProviderBinding(BaseModel):
    provider: str
    instance_id: str
    # The numeric id identifies the group or team; paths and slugs move when one is renamed.
    external_id: int

    @computed_field  # type: ignore[prop-decorator]
    @property
    def key(self) -> str:
        """Stored under the unique index; derived, so it cannot name another binding than its own."""
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


class TeamSyncResult(NamedTuple):
    """``team_ids`` None: the provider could not be asked, so the owners it set stay; ``[]`` retires them."""

    team_ids: list[str] | None


class Team(MongoDocument, CreatedAtModel):
    name: str
    description: str | None = None
    # One entry per instance the team is bound to, of either provider, in any number.
    bindings: list[TeamBinding] = Field(default_factory=list)
    members: list[TeamMember] = Field(default_factory=list)
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    model_config = ConfigDict(arbitrary_types_allowed=True)
