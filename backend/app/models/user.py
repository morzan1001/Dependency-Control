from datetime import datetime

from pydantic import EmailStr, Field

from app.core.constants import AUTH_PROVIDER_LOCAL
from app.core.notification_prefs import NotificationPreferences
from app.models.types import MongoDocument


def is_local_account(auth_provider: str | None) -> bool:
    """A document without a provider predates OIDC, so it is a local account."""
    return (auth_provider or AUTH_PROVIDER_LOCAL) == AUTH_PROVIDER_LOCAL


class User(MongoDocument):
    username: str
    email: EmailStr
    pending_email: str | None = None
    hashed_password: str | None = None
    is_active: bool = True
    is_verified: bool = False
    auth_provider: str = AUTH_PROVIDER_LOCAL  # or the OIDC provider name configured at first login
    permissions: list[str] = Field(default_factory=list)
    last_logout_at: datetime | None = None

    totp_secret: str | None = None
    totp_enabled: bool = False

    slack_username: str | None = None
    mattermost_username: str | None = None
    notification_preferences: NotificationPreferences = Field(default_factory=dict)

    @property
    def is_local(self) -> bool:
        return is_local_account(self.auth_provider)
