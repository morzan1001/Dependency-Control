from pydantic import BaseModel, Field, EmailStr
from typing import Optional
from datetime import datetime
import uuid

class User(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()), alias="_id")
    username: str
    email: EmailStr
    hashed_password: str
    is_active: bool = True
    is_verified: bool = False
    permissions: list[str] = []  # e.g. "project:create", "user:manage"
    last_logout_at: Optional[datetime] = None
    
    # 2FA settings
    totp_secret: Optional[str] = None
    totp_enabled: bool = False

    # Notification settings
    slack_username: Optional[str] = None
    mattermost_username: Optional[str] = None
    notification_preferences: dict[str, list[str]] = Field(
        default_factory=lambda: {
            "analysis_completed": ["email"],
            "vulnerability_found": ["email", "slack"]
        }
    )

    class Config:
        populate_by_name = True
        arbitrary_types_allowed = True
