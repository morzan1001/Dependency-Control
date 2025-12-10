from fastapi import APIRouter, Depends, HTTPException, status, Body
from motor.motor_asyncio import AsyncIOMotorDatabase
from datetime import datetime, timedelta
import uuid
import os

from app.api import deps
from app.core import security
from app.core.config import settings
from app.models.user import User
from app.models.invitation import SystemInvitation
from app.schemas.user import User as UserSchema, UserSignup
from app.db.mongodb import get_database
from app.services.notifications.service import notification_service
from app.services.notifications import templates

router = APIRouter()

@router.post("/system", status_code=status.HTTP_201_CREATED)
async def create_system_invitation(
    email: str = Body(..., embed=True),
    current_user: User = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """
    Create a system invitation for a new user. Requires 'user:manage' permission.
    """
    if "*" not in current_user.permissions and "user:manage" not in current_user.permissions:
        raise HTTPException(status_code=403, detail="Not enough permissions")

    # Check if user already exists
    existing_user = await db.users.find_one({"email": email})
    if existing_user:
        raise HTTPException(status_code=400, detail="User with this email already exists")

    # Check if valid invitation already exists
    existing_invite = await db.system_invitations.find_one({
        "email": email,
        "is_used": False,
        "expires_at": {"$gt": datetime.utcnow()}
    })
    
    if existing_invite:
        # Resend existing invite
        token = existing_invite["token"]
    else:
        # Create new invite
        token = str(uuid.uuid4())
        invitation = SystemInvitation(
            email=email,
            token=token,
            invited_by=current_user.username,
            expires_at=datetime.utcnow() + timedelta(days=7)
        )
        await db.system_invitations.insert_one(invitation.dict(by_alias=True))

    # Send email
    link = f"{settings.FRONTEND_BASE_URL}/accept-invite?token={token}"
    
    current_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.abspath(os.path.join(current_dir, "../../../../.."))
    logo_path = os.path.join(project_root, "assets", "logo.png")
    
    html_content = templates.get_system_invitation_template(
        invitation_link=link,
        project_name=settings.PROJECT_NAME,
        inviter_name=current_user.username
    )
    
    await notification_service.email_provider.send(
        destination=email,
        subject=f"Invitation to join {settings.PROJECT_NAME}",
        message=f"You have been invited to join {settings.PROJECT_NAME}. Click here to accept: {link}",
        html_message=html_content,
        logo_path=logo_path
    )
    
    return {"message": "Invitation sent successfully"}

@router.get("/system/{token}")
async def validate_system_invitation(
    token: str,
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """
    Validate a system invitation token.
    """
    invitation = await db.system_invitations.find_one({
        "token": token,
        "is_used": False,
        "expires_at": {"$gt": datetime.utcnow()}
    })
    
    if not invitation:
        raise HTTPException(status_code=404, detail="Invalid or expired invitation token")
        
    return {"email": invitation["email"]}

@router.post("/system/accept", response_model=UserSchema, status_code=status.HTTP_201_CREATED)
async def accept_system_invitation(
    token: str = Body(...),
    username: str = Body(...),
    password: str = Body(...),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """
    Accept a system invitation and create a user account.
    """
    invitation = await db.system_invitations.find_one({
        "token": token,
        "is_used": False,
        "expires_at": {"$gt": datetime.utcnow()}
    })
    
    if not invitation:
        raise HTTPException(status_code=400, detail="Invalid or expired invitation token")
        
    # Check if username is taken
    if await db.users.find_one({"username": username}):
        raise HTTPException(status_code=400, detail="Username already taken")
        
    # Check if email is taken (shouldn't happen if invite logic is correct, but good to check)
    if await db.users.find_one({"email": invitation["email"]}):
        raise HTTPException(status_code=400, detail="Email already registered")
        
    # Create user
    hashed_password = security.get_password_hash(password)
    new_user = User(
        username=username,
        email=invitation["email"],
        hashed_password=hashed_password,
        is_active=True,
        is_verified=True, # Email is verified via invitation
        permissions=[]
    )
    
    await db.users.insert_one(new_user.dict(by_alias=True))
    
    # Mark invitation as used
    await db.system_invitations.update_one(
        {"_id": invitation["_id"]},
        {"$set": {"is_used": True}}
    )
    
    return new_user
