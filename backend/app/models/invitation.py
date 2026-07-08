from datetime import datetime

from pydantic import ConfigDict, EmailStr

from app.models.base import CreatedAtModel
from app.models.types import MongoDocument


class ProjectInvitation(MongoDocument, CreatedAtModel):
    project_id: str
    email: EmailStr
    role: str
    token: str
    invited_by: str
    expires_at: datetime

    model_config = ConfigDict(arbitrary_types_allowed=True)


class SystemInvitation(MongoDocument, CreatedAtModel):
    email: EmailStr
    token: str
    invited_by: str
    expires_at: datetime
    is_used: bool = False

    model_config = ConfigDict(arbitrary_types_allowed=True)
