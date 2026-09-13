from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field

from app.core.constants import TEAM_ROLE_MEMBER, TeamRole
from app.models.team import TeamBinding
from app.models.types import PyObjectId


class TeamMemberSchema(BaseModel):
    user_id: str
    username: str | None = None
    # Deliberately not TeamRole: read_team serves from an aggregate that bypasses the storage
    # model, so this is the last view that can still render a team holding a pre-existing bad role.
    role: str


class TeamRef(BaseModel):
    """One owning team on a project row. The id travels with the name because a project can be
    listed under several teams and the reader has to be able to tell two same-named ones apart."""

    id: str
    name: str


class TeamBase(BaseModel):
    name: str
    description: str | None = None


class TeamCreate(TeamBase):
    pass


class TeamUpdate(BaseModel):
    name: str | None = None
    description: str | None = None


class TeamGitHubBindingRequest(BaseModel):
    """The team is named by its number; the slug is read back from the organisation listing."""

    provider: Literal["github"]
    instance_id: str
    org: str
    external_id: int


class TeamGitLabBindingRequest(BaseModel):
    """The group is named by its number; the path is read back from the instance."""

    provider: Literal["gitlab"]
    instance_id: str
    external_id: int


TeamBindingRequest = Annotated[
    TeamGitHubBindingRequest | TeamGitLabBindingRequest, Field(discriminator="provider")
]


class TeamResponse(TeamBase):
    id: PyObjectId = Field(validation_alias="_id")
    members: list[TeamMemberSchema]
    created_at: datetime
    updated_at: datetime
    bindings: list[TeamBinding] = Field(default_factory=list)

    model_config = ConfigDict(from_attributes=True, populate_by_name=True)


class TeamMemberAdd(BaseModel):
    email: str
    role: TeamRole = TEAM_ROLE_MEMBER


class TeamMemberUpdate(BaseModel):
    role: TeamRole
