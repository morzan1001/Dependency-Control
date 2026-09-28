import re
from typing import Annotated

from pydantic import AfterValidator, BaseModel, ConfigDict, EmailStr, Field, StringConstraints, field_validator

from app.core.notification_prefs import NotificationPreferences
from app.models.types import PyObjectId
from app.schemas._not_null import reject_null


def validate_password_strength(password: str) -> str:
    """Validate password meets security requirements."""
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


LowercaseEmail = Annotated[EmailStr, AfterValidator(str.lower)]
Username = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]


class UserBase(BaseModel):
    email: EmailStr
    username: str
    is_active: bool | None = True
    auth_provider: str | None = "local"
    permissions: list[str] = []
    slack_username: str | None = None
    mattermost_username: str | None = None
    notification_preferences: NotificationPreferences = None


class UserCreate(UserBase):
    email: LowercaseEmail
    password: str | None = None

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str | None) -> str | None:
        if v is None:
            return v
        return validate_password_strength(v)


class UserSignup(BaseModel):
    email: LowercaseEmail
    username: str
    password: str
    slack_username: str | None = None
    mattermost_username: str | None = None
    notification_preferences: NotificationPreferences = None

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        return validate_password_strength(v)


class UserUpdate(BaseModel):
    email: LowercaseEmail | None = None
    username: Username | None = None
    is_active: bool | None = None
    permissions: list[str] | None = None
    slack_username: str | None = None
    mattermost_username: str | None = None
    notification_preferences: NotificationPreferences = None
    password: str | None = None

    _not_null = field_validator("email", "username", "is_active", "permissions")(reject_null)


class UserUpdateMe(BaseModel):
    model_config = ConfigDict(extra="forbid")

    slack_username: str | None = None
    mattermost_username: str | None = None
    notification_preferences: NotificationPreferences = None


class UserEmailChange(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email: LowercaseEmail


class UserPasswordUpdate(BaseModel):
    current_password: str
    new_password: str

    @field_validator("new_password")
    @classmethod
    def validate_new_password(cls, v: str) -> str:
        return validate_password_strength(v)


class UserMigrateToLocal(BaseModel):
    new_password: str

    @field_validator("new_password")
    @classmethod
    def validate_new_password(cls, v: str) -> str:
        return validate_password_strength(v)


class UserInDBBase(UserBase):
    id: PyObjectId = Field(validation_alias="_id")
    totp_enabled: bool = False
    is_verified: bool = False
    pending_email: str | None = None

    model_config = ConfigDict(from_attributes=True, populate_by_name=True)


class User(UserInDBBase):
    pass


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
    new_password: str

    @field_validator("new_password")
    @classmethod
    def validate_new_password(cls, v: str) -> str:
        return validate_password_strength(v)
