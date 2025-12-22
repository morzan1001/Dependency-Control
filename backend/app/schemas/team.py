from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, Field


class TeamMemberSchema(BaseModel):
    user_id: str
    username: Optional[str] = None
    role: str


class TeamBase(BaseModel):
    name: str
    description: Optional[str] = None


class TeamCreate(TeamBase):
    pass


class TeamUpdate(TeamBase):
    name: Optional[str] = None


class TeamResponse(TeamBase):
    id: str = Field(..., alias="_id")
    members: List[TeamMemberSchema]
    created_at: datetime
    updated_at: datetime

    class Config:
        populate_by_name = True


class TeamMemberAdd(BaseModel):
    email: str
    role: str = "member"


class TeamMemberUpdate(BaseModel):
    role: str
