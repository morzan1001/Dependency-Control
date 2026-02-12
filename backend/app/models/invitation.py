import uuid
from datetime import datetime, timezone

from pydantic import BaseModel, ConfigDict, EmailStr, Field

from app.models.types import PyObjectId


class ProjectInvitation(BaseModel):
    id: PyObjectId = Field(
        default_factory=lambda: str(uuid.uuid4()),
        validation_alias="_id",
        serialization_alias="_id",
    )
    project_id: str
    email: EmailStr
    role: str
    token: str
    invited_by: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime

    model_config = ConfigDict(populate_by_name=True, arbitrary_types_allowed=True)


class SystemInvitation(BaseModel):
    id: PyObjectId = Field(
        default_factory=lambda: str(uuid.uuid4()),
        validation_alias="_id",
        serialization_alias="_id",
    )
    email: EmailStr
    token: str
    invited_by: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime
    is_used: bool = False

    model_config = ConfigDict(populate_by_name=True, arbitrary_types_allowed=True)
