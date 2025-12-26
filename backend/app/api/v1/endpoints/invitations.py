import logging
import os
import uuid
from datetime import datetime, timedelta, timezone
from typing import List

from fastapi import (APIRouter, BackgroundTasks, Body, Depends, HTTPException,
                     status)
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.api import deps
from app.core import security
from app.core.config import settings
from app.db.mongodb import get_database
from app.models.invitation import SystemInvitation
from app.models.system import SystemSettings
from app.models.user import User
from app.schemas.user import User as UserSchema
from app.services.notifications import templates
from app.services.notifications.service import notification_service

router = APIRouter()
logger = logging.getLogger(__name__)


async def get_system_settings(db: AsyncIOMotorDatabase) -> SystemSettings:
    data = await db.system_settings.find_one({"_id": "current"})
    if not data:
        return SystemSettings()
    return SystemSettings(**data)


@router.get("/system", response_model=List[SystemInvitation])
async def read_system_invitations(
    skip: int = 0,
    limit: int = 100,
    current_user: User = Depends(deps.PermissionChecker("user:manage")),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    List all pending system invitations.
    """
    invitations = (
        await db.system_invitations.find(
            {"is_used": False, "expires_at": {"$gt": datetime.now(timezone.utc)}}
        )
        .skip(skip)
        .limit(limit)
        .to_list(limit)
    )
    return invitations


@router.post("/system", status_code=status.HTTP_201_CREATED)
async def create_system_invitation(
    background_tasks: BackgroundTasks,
    email: str = Body(..., embed=True),
    current_user: User = Depends(deps.PermissionChecker("user:manage")),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    Create a system invitation for a new user. Requires 'user:manage' permission.
    """
    # Check if user already exists
    existing_user = await db.users.find_one({"email": email})
    if existing_user:
        raise HTTPException(
            status_code=400, detail="User with this email already exists"
        )

    # Check if valid invitation already exists
    existing_invite = await db.system_invitations.find_one(
        {
            "email": email,
            "is_used": False,
            "expires_at": {"$gt": datetime.now(timezone.utc)},
        }
    )

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
            expires_at=datetime.now(timezone.utc) + timedelta(days=7),
        )
        await db.system_invitations.insert_one(invitation.dict(by_alias=True))

    # Send email
    link = f"{settings.FRONTEND_BASE_URL}/accept-invite?token={token}"

    try:
        current_dir = os.path.dirname(os.path.abspath(__file__))
        project_root = os.path.abspath(os.path.join(current_dir, "../../../../.."))
        logo_path = os.path.join(project_root, "assets", "logo.png")

        html_content = templates.get_system_invitation_template(
            invitation_link=link,
            project_name=settings.PROJECT_NAME,
            inviter_name=current_user.username,
        )

        system_config = await get_system_settings(db)

        background_tasks.add_task(
            notification_service.email_provider.send,
            destination=email,
            subject=f"Invitation to join {settings.PROJECT_NAME}",
            message=f"You have been invited to join {settings.PROJECT_NAME}. Click here to accept: {link}",
            html_message=html_content,
            logo_path=logo_path,
            system_settings=system_config,
        )
    except Exception as e:
        logger.error(f"Failed to send invitation email: {e}")

    return {"message": "Invitation created", "link": link}


@router.get("/system/{token}")
async def validate_system_invitation(
    token: str, db: AsyncIOMotorDatabase = Depends(get_database)
):
    """
    Validate a system invitation token.
    """
    invitation = await db.system_invitations.find_one(
        {
            "token": token,
            "is_used": False,
            "expires_at": {"$gt": datetime.now(timezone.utc)},
        }
    )

    if not invitation:
        raise HTTPException(
            status_code=404, detail="Invalid or expired invitation token"
        )

    return {"email": invitation["email"]}


@router.post(
    "/system/accept", response_model=UserSchema, status_code=status.HTTP_201_CREATED
)
async def accept_system_invitation(
    token: str = Body(...),
    username: str = Body(...),
    password: str = Body(...),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    Accept a system invitation and create a user account.
    """
    invitation = await db.system_invitations.find_one(
        {
            "token": token,
            "is_used": False,
            "expires_at": {"$gt": datetime.now(timezone.utc)},
        }
    )

    if not invitation:
        raise HTTPException(
            status_code=400, detail="Invalid or expired invitation token"
        )

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
        is_verified=True,  # Email is verified via invitation
        permissions=[],
    )

    await db.users.insert_one(new_user.dict(by_alias=True))

    # Mark invitation as used
    await db.system_invitations.update_one(
        {"_id": invitation["_id"]}, {"$set": {"is_used": True}}
    )

    return new_user
