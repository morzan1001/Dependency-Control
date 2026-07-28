from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.models.types import PyObjectId


class TeamMemberSchema(BaseModel):
    user_id: str
    username: str | None = None
    role: str


class TeamBase(BaseModel):
    name: str
    description: str | None = None


class TeamCreate(TeamBase):
    pass


class TeamUpdate(BaseModel):
    name: str | None = None
    description: str | None = None


class TeamResponse(TeamBase):
    id: PyObjectId = Field(validation_alias="_id")
    members: list[TeamMemberSchema]
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True, populate_by_name=True)


class TeamMemberAdd(BaseModel):
    email: str
    role: str = "member"


class TeamMemberUpdate(BaseModel):
    role: str
