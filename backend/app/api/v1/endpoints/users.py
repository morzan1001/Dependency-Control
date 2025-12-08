from fastapi import APIRouter, Depends, HTTPException, status
from typing import List
from motor.motor_asyncio import AsyncIOMotorDatabase
import pyotp
import qrcode
import io
import base64

from app.api import deps
from app.core import security
from app.models.user import User
from app.schemas.user import User as UserSchema, UserUpdate, UserCreate, UserPasswordUpdate, User2FASetup, User2FAVerify, UserUpdateMe
from app.db.mongodb import get_database
from app.services.notifications.service import notification_service
from app.services.notifications import templates
from app.core.config import settings

router = APIRouter()

@router.post("/", response_model=UserSchema, status_code=status.HTTP_201_CREATED)
async def create_user(
    user_in: UserCreate,
    current_user: User = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """
    Create a new user. Requires 'user:manage' permissions.
    """
    if "*" not in current_user.permissions and "user:manage" not in current_user.permissions:
        raise HTTPException(status_code=403, detail="Not enough permissions")

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

@router.get("/", response_model=List[UserSchema])
async def read_users(
    skip: int = 0,
    limit: int = 100,
    current_user: User = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    if "*" not in current_user.permissions and "user:manage" not in current_user.permissions:
        raise HTTPException(status_code=403, detail="Not enough permissions")
    users = await db.users.find().skip(skip).limit(limit).to_list(limit)
    return users

@router.get("/me", response_model=UserSchema)
async def read_user_me(
    current_user: User = Depends(deps.get_current_active_user),
):
    """
    Get current user.
    """
    return current_user

@router.patch("/me", response_model=UserSchema)
async def update_user_me(
    user_in: UserUpdateMe,
    current_user: User = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """
    Update own profile.
    """
    # Check if email is being updated and if it's unique
    if user_in.email and user_in.email != current_user.email:
        existing_user = await db.users.find_one({"email": user_in.email})
        if existing_user:
            raise HTTPException(status_code=400, detail="Email already registered")
            
    # Check if username is being updated and if it's unique
    if user_in.username and user_in.username != current_user.username:
        existing_user = await db.users.find_one({"username": user_in.username})
        if existing_user:
            raise HTTPException(status_code=400, detail="Username already taken")

    update_data = user_in.dict(exclude_unset=True)
    
    if update_data:
        await db.users.update_one({"_id": current_user.id}, {"$set": update_data})
        
    updated_user = await db.users.find_one({"_id": current_user.id})
    return updated_user

@router.get("/{user_id}", response_model=UserSchema)
async def read_user_by_id(
    user_id: str,
    current_user: User = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    has_admin_perm = "*" in current_user.permissions or "user:manage" in current_user.permissions
    if not has_admin_perm and str(current_user.id) != user_id:
        raise HTTPException(status_code=403, detail="Not enough permissions")
        
    user = await db.users.find_one({"_id": user_id})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user

@router.put("/{user_id}", response_model=UserSchema)
async def update_user(
    user_id: str,
    user_in: UserUpdate,
    current_user: User = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    has_admin_perm = "*" in current_user.permissions or "user:manage" in current_user.permissions
    if not has_admin_perm and str(current_user.id) != user_id:
        raise HTTPException(status_code=403, detail="Not enough permissions")
        
    user = await db.users.find_one({"_id": user_id})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
        
    update_data = user_in.dict(exclude_unset=True)
    if "password" in update_data:
        hashed_password = security.get_password_hash(update_data.pop("password"))
        update_data["hashed_password"] = hashed_password

    if update_data:
        await db.users.update_one({"_id": user_id}, {"$set": update_data})
        
    updated_user = await db.users.find_one({"_id": user_id})
    return updated_user

@router.post("/me/password", response_model=UserSchema)
async def update_password_me(
    password_in: UserPasswordUpdate,
    current_user: User = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """
    Update current user password.
    """
    if not security.verify_password(password_in.current_password, current_user.hashed_password):
        raise HTTPException(status_code=400, detail="Incorrect password")
    
    hashed_password = security.get_password_hash(password_in.new_password)
    
    await db.users.update_one(
        {"_id": current_user.id}, 
        {"$set": {"hashed_password": hashed_password}}
    )
    
    # Send notification
    await notification_service.email_provider.send(
        destination=current_user.email,
        subject="Security Alert: Password Changed",
        message=f"Hello {current_user.username},\n\nYour password for Dependency Control was successfully changed.\n\nIf you did not initiate this change, please contact your administrator immediately.",
        html_message=templates.get_password_changed_template(
            username=current_user.username,
            login_link=f"{settings.FRONTEND_BASE_URL}/login",
            project_name=settings.PROJECT_NAME
        )
    )

    updated_user = await db.users.find_one({"_id": current_user.id})
    return updated_user

@router.post("/me/2fa/setup", response_model=User2FASetup)
async def setup_2fa(
    current_user: User = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """
    Generate a new 2FA secret and QR code.
    """
    secret = pyotp.random_base32()
    
    # Save secret to user but don't enable yet
    await db.users.update_one(
        {"_id": current_user.id},
        {"$set": {"totp_secret": secret}}
    )
    
    # Generate QR Code
    totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=current_user.email,
        issuer_name="DependencyControl"
    )
    
    img = qrcode.make(totp_uri)
    buffered = io.BytesIO()
    img.save(buffered, format="PNG")
    qr_code_base64 = base64.b64encode(buffered.getvalue()).decode("utf-8")
    
    return {"secret": secret, "qr_code": qr_code_base64}

@router.post("/me/2fa/enable", response_model=UserSchema)
async def enable_2fa(
    verify_in: User2FAVerify,
    current_user: User = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """
    Verify OTP and enable 2FA.
    """
    user = await db.users.find_one({"_id": current_user.id})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    secret = user.get("totp_secret")
    
    if not secret:
        raise HTTPException(status_code=400, detail="2FA setup not initiated")
        
    totp = pyotp.TOTP(secret)
    if not totp.verify(verify_in.code, valid_window=1):
        raise HTTPException(status_code=400, detail="Invalid OTP code")
        
    await db.users.update_one(
        {"_id": current_user.id},
        {"$set": {"totp_enabled": True}}
    )
    
    # Send notification
    await notification_service.email_provider.send(
        destination=current_user.email,
        subject="Security Alert: 2FA Enabled",
        message=f"Hello {current_user.username},\n\nTwo-Factor Authentication (2FA) has been enabled for your account.\n\nIf you did not initiate this change, please contact your administrator immediately.",
        html_message=templates.get_2fa_enabled_template(
            username=current_user.username,
            project_name=settings.PROJECT_NAME
        )
    )

    updated_user = await db.users.find_one({"_id": current_user.id})
    return updated_user

@router.post("/me/2fa/disable", response_model=UserSchema)
async def disable_2fa(
    current_user: User = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """
    Disable 2FA.
    """
    await db.users.update_one(
        {"_id": current_user.id},
        {"$set": {"totp_enabled": False, "totp_secret": None}}
    )
    
    # Send notification
    await notification_service.email_provider.send(
        destination=current_user.email,
        subject="Security Alert: 2FA Disabled",
        message=f"Hello {current_user.username},\n\nTwo-Factor Authentication (2FA) has been disabled for your account.\n\nIf you did not initiate this change, please contact your administrator immediately.",
        html_message=templates.get_2fa_disabled_template(
            username=current_user.username,
            project_name=settings.PROJECT_NAME
        )
    )

    updated_user = await db.users.find_one({"_id": current_user.id})
    return updated_user

@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(
    user_id: str,
    current_user: User = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """
    Delete a user. Requires 'user:manage' permissions.
    """
    if "*" not in current_user.permissions and "user:manage" not in current_user.permissions:
        raise HTTPException(status_code=403, detail="Not enough permissions")
        
    if user_id == str(current_user.id):
        raise HTTPException(status_code=400, detail="Users cannot delete themselves")

    user = await db.users.find_one({"_id": user_id})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
        
    await db.users.delete_one({"_id": user_id})
    return None

