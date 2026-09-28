import logging
from datetime import datetime

from pydantic import ConfigDict, EmailStr, Field

from app.core.constants import AUTH_PROVIDER_LOCAL
from app.core.notification_prefs import NotificationPreferences
from app.models.types import MongoDocument

logger = logging.getLogger(__name__)


def is_local_account(auth_provider: str | None) -> bool:
    """Whether password, 2FA and email verification apply; a document without a provider predates OIDC."""
    return (auth_provider or AUTH_PROVIDER_LOCAL) == AUTH_PROVIDER_LOCAL


class User(MongoDocument):
    username: str
    email: EmailStr
    pending_email: str | None = None
    hashed_password: str | None = None
    is_active: bool = True
    is_verified: bool = False
    auth_provider: str = AUTH_PROVIDER_LOCAL  # or the OIDC provider name configured at first login
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

    @property
    def is_local(self) -> bool:
        return is_local_account(self.auth_provider)
