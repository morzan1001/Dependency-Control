from datetime import datetime

from pydantic import EmailStr

from app.models.base import CreatedAtModel
from app.models.types import MongoDocument


class SystemInvitation(MongoDocument, CreatedAtModel):
    email: EmailStr
    token: str
    invited_by: str
    expires_at: datetime
    is_used: bool = False
