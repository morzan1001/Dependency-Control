from pydantic import BaseModel, EmailStr, field_validator
from typing import Optional
import re

class UserBase(BaseModel):
    email: EmailStr
    username: str
    is_active: Optional[bool] = True
    permissions: list[str] = []
    slack_username: Optional[str] = None
    mattermost_username: Optional[str] = None
    notification_preferences: Optional[dict[str, list[str]]] = None

class UserCreate(UserBase):
    password: str

    @field_validator('password')
    def validate_password(cls, v):
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters long')
        if not re.search(r"[A-Z]", v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not re.search(r"[a-z]", v):
            raise ValueError('Password must contain at least one lowercase letter')
        if not re.search(r"\d", v):
            raise ValueError('Password must contain at least one digit')
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", v):
            raise ValueError('Password must contain at least one special character')
        return v

class UserUpdate(UserBase):
    password: Optional[str] = None
    permissions: Optional[list[str]] = None

class UserPasswordUpdate(BaseModel):
    current_password: str
    new_password: str

    @field_validator('new_password')
    def validate_new_password(cls, v):
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters long')
        if not re.search(r"[A-Z]", v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not re.search(r"[a-z]", v):
            raise ValueError('Password must contain at least one lowercase letter')
        if not re.search(r"\d", v):
            raise ValueError('Password must contain at least one digit')
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", v):
            raise ValueError('Password must contain at least one special character')
        return v

class UserInDBBase(UserBase):
    id: str
    totp_enabled: bool = False

    class Config:
        from_attributes = True

class User(UserInDBBase):
    pass

class UserInDB(UserInDBBase):
    hashed_password: str

class User2FASetup(BaseModel):
    secret: str
    qr_code: str

class User2FAVerify(BaseModel):
    code: str

