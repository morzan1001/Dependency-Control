import logging
from datetime import datetime

from pydantic import ConfigDict, EmailStr, Field

from app.core.notification_prefs import NotificationPreferences
from app.models.types import MongoDocument

logger = logging.getLogger(__name__)


class User(MongoDocument):
    username: str
    email: EmailStr
    hashed_password: str | None = None
    is_active: bool = True
    is_verified: bool = False
    auth_provider: str = "local"  # "local", "gitlab", "google", etc.
    permissions: list[str] = Field(default_factory=list)  # e.g. "project:create", "user:read_all"
    last_logout_at: datetime | None = None

    # 2FA settings
    totp_secret: str | None = None
    totp_enabled: bool = False

    # Notification settings
    slack_username: str | None = None
    mattermost_username: str | None = None
    notification_preferences: NotificationPreferences = Field(default_factory=dict)

    model_config = ConfigDict(arbitrary_types_allowed=True)
