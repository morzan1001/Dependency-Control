import logging
import secrets
from datetime import datetime, timedelta, timezone
from typing import List

from fastapi import APIRouter, BackgroundTasks, Body, Depends, HTTPException, status
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.api import deps
from app.api.v1.helpers.auth import send_system_invitation_email
from app.core import security
from app.core.config import settings
from app.db.mongodb import get_database
from app.models.invitation import SystemInvitation
from app.models.user import User
from app.repositories import InvitationRepository, UserRepository
from app.schemas.user import User as UserSchema

router = APIRouter()
logger = logging.getLogger(__name__)


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
    invitation_repo = InvitationRepository(db)
    invitations = await invitation_repo.find_active_system_invitations(
        skip=skip, limit=limit
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
    user_repo = UserRepository(db)
    invitation_repo = InvitationRepository(db)

    # Check if user already exists
    if await user_repo.exists_by_email(email):
        raise HTTPException(
            status_code=400, detail="User with this email already exists"
        )

    # Check if valid invitation already exists
    existing_invite = await invitation_repo.get_system_invitation_by_email(email)

    if existing_invite:
        # Resend existing invite
        token = existing_invite["token"]
    else:
        token = secrets.token_urlsafe(32)  # 32 bytes = 256 bits of entropy
        invitation = SystemInvitation(
            email=email,
            token=token,
            invited_by=current_user.username,
            expires_at=datetime.now(timezone.utc) + timedelta(days=7),
        )
        await invitation_repo.create_system_invitation(invitation)

    # Send invitation email
    link = f"{settings.FRONTEND_BASE_URL}/accept-invite?token={token}"
    email_sent = True

    try:
        system_config = await deps.get_system_settings(db)
        await send_system_invitation_email(
            background_tasks=background_tasks,
            email=email,
            invitation_link=link,
            inviter_name=current_user.username,
            system_settings=system_config,
        )
    except Exception as e:
        email_sent = False
        logger.error(f"Failed to send invitation email: {e}")

    response = {"message": "Invitation created", "link": link}
    if not email_sent:
        response["warning"] = "Email could not be sent. Share the link manually."
    return response


@router.get("/system/{token}")
async def validate_system_invitation(
    token: str, db: AsyncIOMotorDatabase = Depends(get_database)
):
    """
    Validate a system invitation token.
    """
    invitation_repo = InvitationRepository(db)
    invitation = await invitation_repo.get_system_invitation_by_token(token)

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
    user_repo = UserRepository(db)
    invitation_repo = InvitationRepository(db)

    invitation = await invitation_repo.get_system_invitation_by_token(token)

    if not invitation:
        raise HTTPException(
            status_code=400, detail="Invalid or expired invitation token"
        )

    # Check if username is taken
    if await user_repo.exists_by_username(username):
        raise HTTPException(status_code=400, detail="Username already taken")

    # Check if email is taken (shouldn't happen if invite logic is correct, but good to check)
    if await user_repo.exists_by_email(invitation["email"]):
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

    await user_repo.create(new_user)

    # Mark invitation as used
    await invitation_repo.mark_system_invitation_used(invitation["_id"])

    return new_user
