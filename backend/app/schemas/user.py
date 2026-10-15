import re
from typing import Annotated, Literal

from pydantic import AfterValidator, BaseModel, ConfigDict, EmailStr, Field, StringConstraints, field_validator

from app.core.constants import AUTH_PROVIDER_LOCAL
from app.core.notification_prefs import NotificationPreferences, StrictNotificationPreferences
from app.models.types import PyObjectId
from app.schemas._not_null import reject_null


def validate_password_strength(password: str) -> str:
    if len(password) < 8:
        raise ValueError("Password must be at least 8 characters long")
    if not re.search(r"[A-Z]", password):
        raise ValueError("Password must contain at least one uppercase letter")
    if not re.search(r"[a-z]", password):
        raise ValueError("Password must contain at least one lowercase letter")
    if not re.search(r"\d", password):
        raise ValueError("Password must contain at least one digit")
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>\-_+=\[\]\\;'`~/]", password):
        raise ValueError("Password must contain at least one special character")
    return password


# No '@': login resolves the username before the email, so an email-shaped name would shadow that account.
_NEW_USERNAME = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]| (?=[A-Za-z0-9._-])){1,63}")
_USERNAME_RULE = "A username has 2 to 64 letters, digits, dots, underscores, hyphens or single spaces and starts with a letter or digit"


def check_new_username(username: str) -> str:
    if not _NEW_USERNAME.fullmatch(username):
        raise ValueError(_USERNAME_RULE)
    return username


LowercaseEmail = Annotated[EmailStr, AfterValidator(str.lower)]
# A stored name stays valid as it is; only a name someone picks has to follow the rule.
Username = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]
NewUsername = Annotated[Username, AfterValidator(check_new_username)]
StrongPassword = Annotated[str, AfterValidator(validate_password_strength)]


class UserCreate(BaseModel):
    """An administrator creates password accounts only; identity-provider accounts appear at first login."""

    model_config = ConfigDict(extra="forbid")

    email: LowercaseEmail
    username: NewUsername
    password: StrongPassword
    is_active: bool = True
    permissions: list[str] = []
    slack_username: str | None = None
    mattermost_username: str | None = None
    notification_preferences: StrictNotificationPreferences = None


class UserSignup(BaseModel):
    email: LowercaseEmail
    username: NewUsername
    password: StrongPassword
    slack_username: str | None = None
    mattermost_username: str | None = None
    notification_preferences: StrictNotificationPreferences = None


class UserUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email: LowercaseEmail | None = None
    username: Username | None = None
    is_active: bool | None = None
    permissions: list[str] | None = None
    slack_username: str | None = None
    mattermost_username: str | None = None
    notification_preferences: StrictNotificationPreferences = None

    _not_null = field_validator("email", "username", "is_active", "permissions")(reject_null)


class UserUpdateMe(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: Username | None = None
    slack_username: str | None = None
    mattermost_username: str | None = None
    notification_preferences: StrictNotificationPreferences = None

    _not_null = field_validator("username")(reject_null)


class UserEmailChange(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email: LowercaseEmail


class UserPasswordUpdate(BaseModel):
    current_password: str
    new_password: StrongPassword


class UserMigrateToLocal(BaseModel):
    new_password: StrongPassword


class UserResponse(BaseModel):
    id: PyObjectId = Field(validation_alias="_id")
    email: EmailStr
    username: str
    is_active: bool | None = True
    auth_provider: str | None = AUTH_PROVIDER_LOCAL
    permissions: list[str] = []
    slack_username: str | None = None
    mattermost_username: str | None = None
    notification_preferences: NotificationPreferences = None
    totp_enabled: bool = False
    is_verified: bool = False
    pending_email: str | None = None

    model_config = ConfigDict(from_attributes=True, populate_by_name=True)


class EmailChangeResponse(UserResponse):
    email_change: Literal["pending_confirmation", "changed"]


class User2FASetup(BaseModel):
    secret: str
    qr_code: str


class User2FAVerify(BaseModel):
    code: str
    password: str


class User2FADisable(BaseModel):
    password: str


class UserPasswordReset(BaseModel):
    token: str
    new_password: StrongPassword
