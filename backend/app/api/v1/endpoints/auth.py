from datetime import timedelta, datetime
from typing import Any, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Body, Form
from fastapi.security import OAuth2PasswordRequestForm
from motor.motor_asyncio import AsyncIOMotorDatabase
from jose import jwt, JWTError
from pydantic import ValidationError
import pyotp

from app.core import security
from app.core.config import settings
from app.db.mongodb import get_database
from app.schemas.token import Token, TokenPayload
from app.models.user import User
from app.schemas.user import UserCreate, User as UserSchema
from app.api import deps

router = APIRouter()

@router.post("/login/access-token", response_model=Token, summary="Login to get access token")
async def login_access_token(
    db: AsyncIOMotorDatabase = Depends(get_database),
    form_data: OAuth2PasswordRequestForm = Depends(),
    otp: Optional[str] = Form(None)
) -> Any:
    """
    OAuth2 compatible token login, get an access token for future requests.
    
    - **username**: Email or username
    - **password**: User password
    - **otp**: One Time Password (if 2FA is enabled)
    """
    user = await db.users.find_one({"username": form_data.username})
    if not user or not security.verify_password(form_data.password, user["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Check 2FA
    if user.get("totp_enabled", False):
        if not otp:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="2FA required",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        totp = pyotp.TOTP(user["totp_secret"])
        if not totp.verify(otp):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid OTP code",
                headers={"WWW-Authenticate": "Bearer"},
            )
    
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    
    permissions = user.get("permissions", [])
        
    access_token = security.create_access_token(
        user["username"], 
        permissions=permissions,
        expires_delta=access_token_expires
    )
    
    refresh_token = security.create_refresh_token(
        user["username"]
    )
    
    return {
        "access_token": access_token, 
        "refresh_token": refresh_token,
        "token_type": "bearer"
    }

@router.post("/login/refresh-token", response_model=Token, summary="Refresh access token")
async def refresh_token(
    refresh_token: str = Body(..., embed=True, description="The refresh token obtained during login"),
    db: AsyncIOMotorDatabase = Depends(get_database)
) -> Any:
    """
    Get a new access token using a valid refresh token.
    """
    try:
        payload = jwt.decode(
            refresh_token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM]
        )
        token_data = TokenPayload(**payload)
    except (JWTError, ValidationError):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Could not validate credentials",
        )
        
    if token_data.type != "refresh":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid token type",
        )
        
    user = await db.users.find_one({"username": token_data.sub})
    if not user:
        raise HTTPException(
            status_code=404,
            detail="User not found",
        )
        
    # Check if refresh token was issued before last logout
    if "last_logout_at" in user and user["last_logout_at"]:
        iat = payload.get("iat")
        if iat:
            last_logout_ts = user["last_logout_at"].timestamp()
            if iat < last_logout_ts:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Token revoked",
                )
        
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    
    permissions = user.get("permissions", [])

    access_token = security.create_access_token(
        user["username"], 
        permissions=permissions,
        expires_delta=access_token_expires
    )
    
    # Optionally rotate refresh token here
    new_refresh_token = security.create_refresh_token(
        user["username"]
    )
    
    return {
        "access_token": access_token, 
        "refresh_token": new_refresh_token,
        "token_type": "bearer"
    }

@router.post("/signup", response_model=UserSchema, summary="Register a new user")
async def create_user(
    user_in: UserCreate,
    db: AsyncIOMotorDatabase = Depends(get_database)
) -> Any:
    """
    Create a new user in the system.
    """
    user = await db.users.find_one({"username": user_in.username})
    if user:
        raise HTTPException(
            status_code=400,
            detail="The user with this username already exists in the system.",
        )
    user_dict = user_in.dict()
    hashed_password = security.get_password_hash(user_dict.pop("password"))
    user_dict["hashed_password"] = hashed_password
    
    new_user = User(**user_dict)
    await db.users.insert_one(new_user.dict(by_alias=True))
    return new_user

@router.post("/logout", summary="Logout user")
async def logout(
    current_user: User = Depends(deps.get_current_user),
    db: AsyncIOMotorDatabase = Depends(get_database)
) -> Any:
    """
    Logout the current user.
    Invalidates all tokens issued before this logout by updating the user's last_logout_at timestamp.
    """
    await db.users.update_one(
        {"_id": current_user.id},
        {"$set": {"last_logout_at": datetime.utcnow()}}
    )
    return {"message": "Successfully logged out"}

