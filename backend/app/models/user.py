import uuid
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, EmailStr, Field, field_validator


class User(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()), alias="_id")
    username: str
    email: EmailStr
    hashed_password: Optional[str] = None
    is_active: bool = True
    is_verified: bool = False
    auth_provider: str = "local"  # "local", "gitlab", "google", etc.
    permissions: list[str] = []  # e.g. "project:create", "user:manage"
    last_logout_at: Optional[datetime] = None

    # 2FA settings
    totp_secret: Optional[str] = None
    totp_enabled: bool = False

    # Notification settings
    slack_username: Optional[str] = None
    mattermost_username: Optional[str] = None
    notification_preferences: Optional[dict[str, list[str]]] = Field(
        default_factory=lambda: {
            "analysis_completed": ["email"],
            "vulnerability_found": ["email", "slack"],
        }
    )

    @field_validator("id", mode="before")
    @classmethod
    def convert_objectid(cls, v):
        if not isinstance(v, str):
            return str(v)
        return v

    class Config:
        populate_by_name = True
        arbitrary_types_allowed = True
