from pydantic import BaseModel, Field, EmailStr
from typing import Optional
from datetime import datetime
import uuid

class ProjectInvitation(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()), alias="_id")
    project_id: str
    email: EmailStr
    role: str
    token: str
    invited_by: str
    created_at: datetime = Field(default_factory=datetime.utcnow)
    expires_at: datetime

    class Config:
        populate_by_name = True
        arbitrary_types_allowed = True
