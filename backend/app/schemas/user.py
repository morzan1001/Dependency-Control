import re
from typing import Optional

from pydantic import BaseModel, EmailStr, Field, field_validator


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
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        raise ValueError("Password must contain at least one special character")
    return password


class UserBase(BaseModel):
    email: EmailStr
    username: str
    is_active: Optional[bool] = True
    auth_provider: Optional[str] = "local"
    permissions: list[str] = []
    slack_username: Optional[str] = None
    mattermost_username: Optional[str] = None
    notification_preferences: Optional[dict[str, list[str]]] = None


class UserCreate(UserBase):
    password: str

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        return validate_password_strength(v)


class UserSignup(BaseModel):
    email: EmailStr
    username: str
    password: str

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        return validate_password_strength(v)


class UserUpdate(BaseModel):
    email: Optional[EmailStr] = None
    username: Optional[str] = None
    is_active: Optional[bool] = None
    permissions: Optional[list[str]] = None
    slack_username: Optional[str] = None
    mattermost_username: Optional[str] = None
    notification_preferences: Optional[dict[str, list[str]]] = None
    password: Optional[str] = None


class UserUpdateMe(BaseModel):
    email: Optional[EmailStr] = None
    username: Optional[str] = None
    slack_username: Optional[str] = None
    mattermost_username: Optional[str] = None
    notification_preferences: Optional[dict[str, list[str]]] = None


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
    id: str = Field(alias="_id")
    totp_enabled: bool = False
    is_verified: bool = False

    class Config:
        from_attributes = True
        populate_by_name = True


class User(UserInDBBase):
    pass


class UserInDB(UserInDBBase):
    hashed_password: str


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
