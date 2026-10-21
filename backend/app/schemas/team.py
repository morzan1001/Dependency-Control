from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.core.constants import TEAM_ROLE_MEMBER, TeamRole
from app.models.team import TeamBinding
from app.models.types import PyObjectId
from app.schemas._not_null import reject_null


class TeamMemberSchema(BaseModel):
    user_id: str
    username: str | None = None
    # Deliberately not TeamRole, so a team stored with a bad role still renders; reads bypass the storage model.
    role: str
    # "manual", or the "<provider>:<instance id>" of the sync that owns the entry.
    source: str | None = None
    # A live sync restores the entry, so its role and membership change only at the source.
    sync_owned: bool = False


class TeamRef(BaseModel):
    """The id travels with the name, so a reader can tell two same-named owning teams apart."""

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

    _not_null = field_validator("name")(reject_null)


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


TeamBindingRequest = Annotated[TeamGitHubBindingRequest | TeamGitLabBindingRequest, Field(discriminator="provider")]


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
