import logging
import secrets
from datetime import datetime, timedelta, timezone
from typing import Annotated, Any

from fastapi import BackgroundTasks, Body, Depends, HTTPException, status

from app.api import deps
from app.api.deps import DatabaseDep
from app.api.router import CustomAPIRouter
from app.api.v1.helpers.auth import send_system_invitation_email
from app.api.v1.helpers.responses import RESP_400, RESP_404, RESP_AUTH, RESP_AUTH_400, RESP_AUTH_404
from app.core import security
from app.core.config import settings
from app.core.permissions import Permissions
from app.models.invitation import SystemInvitation
from app.models.user import User
from app.repositories.invitations import InvitationRepository
from app.repositories.users import IdentityTakenError, UserRepository
from app.schemas.user import LowercaseEmail, Username, UserResponse

router = CustomAPIRouter()
logger = logging.getLogger(__name__)


@router.get("/system", response_model=list[SystemInvitation], responses=RESP_AUTH)
async def read_system_invitations(
    db: DatabaseDep,
    current_user: Annotated[User, Depends(deps.PermissionChecker(Permissions.USER_CREATE))],
    skip: int = 0,
    limit: int = 100,
) -> list[dict[str, Any]]:
    """List all pending system invitations. Requires 'user:create' permission."""
    invitation_repo = InvitationRepository(db)
    return await invitation_repo.find_active_system_invitations(skip=skip, limit=limit)


@router.post("/system", status_code=status.HTTP_201_CREATED, responses=RESP_AUTH_400)
async def create_system_invitation(
    background_tasks: BackgroundTasks,
    db: DatabaseDep,
    current_user: Annotated[User, Depends(deps.PermissionChecker(Permissions.USER_CREATE))],
    email: Annotated[LowercaseEmail, Body(..., embed=True)],
) -> dict[str, Any]:
    """Create a system invitation for a new user. Requires 'user:create' permission."""
    invitation_repo = InvitationRepository(db)

    # An invitation writes no user, so no unique index refuses a registered address here.
    if await UserRepository(db).exists_by_email(email):
        raise IdentityTakenError("email")

    existing_invite = await invitation_repo.get_system_invitation_by_email(email)

    if existing_invite:
        token = existing_invite["token"]
    else:
        token = secrets.token_urlsafe(32)
        invitation = SystemInvitation(
            email=email,
            token=token,
            invited_by=current_user.username,
            expires_at=datetime.now(timezone.utc) + timedelta(days=7),
        )
        await invitation_repo.create_system_invitation(invitation)

    link = f"{settings.FRONTEND_BASE_URL}/accept-invite?token={token}"
    email_sent = True

    try:
        system_config = await deps.get_system_settings(db)
        send_system_invitation_email(
            background_tasks=background_tasks,
            email=email,
            invitation_link=link,
            inviter_name=current_user.username,
            system_settings=system_config,
        )
    except Exception as e:
        email_sent = False
        logger.exception("Failed to send invitation email: %s", e)

    response = {"message": "Invitation created", "link": link}
    if not email_sent:
        response["warning"] = "Email could not be sent. Share the link manually."
    return response


@router.delete("/system/{invitation_id}", status_code=status.HTTP_204_NO_CONTENT, responses=RESP_AUTH_404)
async def revoke_system_invitation(
    invitation_id: str,
    db: DatabaseDep,
    current_user: Annotated[User, Depends(deps.PermissionChecker(Permissions.USER_CREATE))],
) -> None:
    """Revoke a pending system invitation. Requires 'user:create' permission."""
    if not await InvitationRepository(db).delete_system_invitation(invitation_id):
        raise HTTPException(status_code=404, detail="Invitation not found")


@router.get("/system/{token}", responses=RESP_404)
async def validate_system_invitation(token: str, db: DatabaseDep) -> dict[str, Any]:
    """Validate a system invitation token."""
    invitation_repo = InvitationRepository(db)
    invitation = await invitation_repo.get_system_invitation_by_token(token)

    if not invitation:
        raise HTTPException(status_code=404, detail="Invalid or expired invitation token")

    return {"email": invitation["email"]}


@router.post("/system/accept", response_model=UserResponse, status_code=status.HTTP_201_CREATED, responses=RESP_400)
async def accept_system_invitation(
    db: DatabaseDep,
    token: Annotated[str, Body(...)],
    username: Annotated[Username, Body(...)],
    password: Annotated[str, Body(...)],
) -> User:
    """Accept a system invitation and create a user account."""
    invitation_repo = InvitationRepository(db)

    invitation = await invitation_repo.get_system_invitation_by_token(token)

    if not invitation:
        raise HTTPException(status_code=400, detail="Invalid or expired invitation token")

    hashed_password = security.get_password_hash(password)
    new_user = User(
        username=username,
        email=invitation["email"],
        hashed_password=hashed_password,
        is_active=True,
        is_verified=True,  # verified via invitation
        permissions=[],
    )

    await UserRepository(db).create(new_user)

    await invitation_repo.mark_system_invitation_used(invitation["_id"])

    return new_user
