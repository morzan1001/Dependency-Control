import base64
import io
import logging
import re
from typing import List, Optional

import pyotp
import qrcode
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.api import deps
from app.api.v1.helpers import (
    check_admin_or_self,
    fetch_updated_user,
    get_logo_path,
    get_user_or_404,
    is_2fa_setup_mode,
)
from app.core import security
from app.core.config import settings
from app.core.constants import AUTH_PROVIDER_LOCAL
from app.db.mongodb import get_database
from app.models.user import User
from app.repositories import InvitationRepository, UserRepository
from app.schemas.user import User as UserSchema
from app.schemas.user import (
    User2FADisable,
    User2FASetup,
    User2FAVerify,
    UserCreate,
    UserMigrateToLocal,
    UserPasswordUpdate,
    UserUpdate,
    UserUpdateMe,
)
from app.services.notifications import templates
from app.services.notifications.email_provider import EmailProvider
from app.services.notifications.service import notification_service
from app.services.notifications.templates import get_password_reset_template

router = APIRouter()
logger = logging.getLogger(__name__)


@router.post("/", response_model=UserSchema, status_code=status.HTTP_201_CREATED)
async def create_user(
    user_in: UserCreate,
    current_user: User = Depends(
        deps.PermissionChecker(["user:manage", "user:create"])
    ),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    Create a new user. Requires 'user:manage' or 'user:create' permissions.
    """
    if not user_in.password:
        raise HTTPException(
            status_code=400,
            detail="Password is required when creating a user",
        )

    user_repo = UserRepository(db)

    if await user_repo.exists_by_email(user_in.email):
        raise HTTPException(
            status_code=400,
            detail="A user with this email already exists in the system.",
        )

    if await user_repo.exists_by_username(user_in.username):
        raise HTTPException(
            status_code=400,
            detail="A user with this username already exists in the system.",
        )

    user_dict = user_in.model_dump()
    hashed_password = security.get_password_hash(user_dict.pop("password"))
    user_dict["hashed_password"] = hashed_password

    new_user = User(**user_dict)
    await user_repo.create(new_user)
    return new_user


@router.get("/", response_model=List[UserSchema])
async def read_users(
    skip: int = 0,
    limit: int = 100,
    search: Optional[str] = None,
    sort_by: str = "username",
    sort_order: str = "asc",
    current_user: User = Depends(
        deps.PermissionChecker(["user:manage", "user:read_all"])
    ),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    query = {}
    if search:
        escaped_search = re.escape(search)
        query = {
            "$or": [
                {"username": {"$regex": escaped_search, "$options": "i"}},
                {"email": {"$regex": escaped_search, "$options": "i"}},
            ]
        }

    sort_direction = 1 if sort_order == "asc" else -1

    user_repo = UserRepository(db)
    users = await user_repo.find_many(
        query, skip=skip, limit=limit, sort_by=sort_by, sort_order=sort_direction
    )
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
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    Update own profile.
    """
    user_repo = UserRepository(db)

    # Check if email is being updated and if it's unique
    if user_in.email and user_in.email != current_user.email:
        if await user_repo.exists_by_email(user_in.email):
            raise HTTPException(status_code=400, detail="Email already registered")

    # Check if username is being updated and if it's unique
    if user_in.username and user_in.username != current_user.username:
        if await user_repo.exists_by_username(user_in.username):
            raise HTTPException(status_code=400, detail="Username already taken")

    update_data = user_in.model_dump(exclude_unset=True)

    if update_data:
        await user_repo.update(current_user.id, update_data)

    return await fetch_updated_user(current_user.id, db)


@router.get("/{user_id}", response_model=UserSchema)
async def read_user_by_id(
    user_id: str,
    current_user: User = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """Get user by ID. Requires admin permission or self."""
    check_admin_or_self(current_user, user_id, ["user:manage", "user:read"])
    return await get_user_or_404(user_id, db)


@router.put("/{user_id}", response_model=UserSchema)
async def update_user(
    user_id: str,
    user_in: UserUpdate,
    current_user: User = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """Update user. Requires admin permission or self."""
    has_admin_perm = check_admin_or_self(
        current_user, user_id, ["user:manage", "user:update"]
    )

    existing_user = await get_user_or_404(user_id, db)

    user_repo = UserRepository(db)
    update_data = user_in.model_dump(exclude_unset=True)

    # Check email uniqueness if being updated
    if "email" in update_data and update_data["email"] != existing_user.get("email"):
        if await user_repo.exists_by_email(update_data["email"]):
            raise HTTPException(status_code=400, detail="Email already registered")

    # Check username uniqueness if being updated
    if "username" in update_data and update_data["username"] != existing_user.get(
        "username"
    ):
        if await user_repo.exists_by_username(update_data["username"]):
            raise HTTPException(status_code=400, detail="Username already taken")

    if "password" in update_data:
        if has_admin_perm:
            raise HTTPException(
                status_code=400,
                detail=(
                    "Admins cannot set passwords directly. Please use the "
                    "'Reset Password' feature to send a reset link."
                ),
            )
        else:
            raise HTTPException(
                status_code=400,
                detail="Use the /me/password endpoint to change your password.",
            )

    if update_data:
        await user_repo.update(user_id, update_data)

    return await fetch_updated_user(user_id, db)


@router.post("/me/migrate", response_model=UserSchema)
async def migrate_to_local(
    *,
    password_in: UserMigrateToLocal,
    current_user: User = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    Migrate SSO user to local account by setting a password.
    """
    if current_user.auth_provider == AUTH_PROVIDER_LOCAL:
        raise HTTPException(status_code=400, detail="User is already a local account.")

    hashed_password = security.get_password_hash(password_in.new_password)

    user_repo = UserRepository(db)
    await user_repo.update(
        current_user.id,
        {"hashed_password": hashed_password, "auth_provider": AUTH_PROVIDER_LOCAL},
    )

    return await fetch_updated_user(current_user.id, db)


@router.post("/{user_id}/migrate", response_model=UserSchema)
async def migrate_user_to_local(
    user_id: str,
    current_user: User = Depends(
        deps.PermissionChecker(["user:manage", "user:update"])
    ),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    Admin only: Migrate a user to local authentication.
    This does not set a password, but changes the auth_provider to 'local'.
    The admin should then trigger a password reset.
    """
    user = await get_user_or_404(user_id, db)

    if user.get("auth_provider") == AUTH_PROVIDER_LOCAL:
        raise HTTPException(status_code=400, detail="User is already a local account")

    user_repo = UserRepository(db)
    await user_repo.update(user_id, {"auth_provider": AUTH_PROVIDER_LOCAL})

    return await fetch_updated_user(user_id, db)


@router.post("/{user_id}/reset-password")
async def reset_user_password(
    user_id: str,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(
        deps.PermissionChecker(["user:manage", "user:update"])
    ),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    Admin only: Trigger password reset for a user.
    Generates a reset token and link.
    If SMTP is configured, sends an email.
    Always returns the link (so admin can send it manually if needed).
    """
    user = await get_user_or_404(user_id, db)

    if user.get("auth_provider", AUTH_PROVIDER_LOCAL) != AUTH_PROVIDER_LOCAL:
        raise HTTPException(
            status_code=400,
            detail="Cannot reset password for non-local users. Please migrate user first.",
        )

    token = security.create_password_reset_token(user["email"])
    link = f"{settings.FRONTEND_BASE_URL}/reset-password?token={token}"

    email_sent = False
    if settings.SMTP_HOST:
        try:
            logo_path = get_logo_path()

            html_content = get_password_reset_template(
                username=user["username"], link=link, project_name=settings.PROJECT_NAME
            )

            email_provider = EmailProvider()
            background_tasks.add_task(
                email_provider.send,
                destination=user["email"],
                subject=f"Password Reset for {settings.PROJECT_NAME}",
                message=f"Please reset your password by clicking this link: {link}",
                html_message=html_content,
                logo_path=logo_path,
            )
            email_sent = True
        except Exception as e:
            logger.error(f"Failed to send password reset email: {e}")
            # We continue to return the link

    response = {"message": "Password reset initiated", "email_sent": email_sent}

    if not email_sent:
        response["reset_link"] = link

    return response


@router.post("/me/password", response_model=UserSchema)
async def update_password_me(
    password_in: UserPasswordUpdate,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    Update current user password.
    """
    if current_user.auth_provider != AUTH_PROVIDER_LOCAL:
        raise HTTPException(
            status_code=400,
            detail="SSO users cannot change password. Please migrate to local account first.",
        )

    if not security.verify_password(
        password_in.current_password, current_user.hashed_password
    ):
        raise HTTPException(status_code=400, detail="Incorrect password")

    hashed_password = security.get_password_hash(password_in.new_password)

    user_repo = UserRepository(db)
    await user_repo.update(current_user.id, {"hashed_password": hashed_password})

    # Send notification if SMTP is configured
    if settings.SMTP_HOST:
        background_tasks.add_task(
            notification_service.email_provider.send,
            destination=current_user.email,
            subject="Security Alert: Password Changed",
            message=(
                f"Hello {current_user.username},\n\nYour password for {settings.PROJECT_NAME} "
                "was successfully changed.\n\nIf you did not initiate this change, "
                "please contact your administrator immediately."
            ),
            html_message=templates.get_password_changed_template(
                username=current_user.username,
                login_link=f"{settings.FRONTEND_BASE_URL}/login",
                project_name=settings.PROJECT_NAME,
            ),
        )

    return await fetch_updated_user(current_user.id, db)


@router.post("/me/2fa/setup", response_model=User2FASetup)
async def setup_2fa(
    current_user: User = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    Generate a new 2FA secret and QR code.
    """
    # User must be either in 2FA setup mode or be a fully active user
    if not is_2fa_setup_mode(current_user) and not current_user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")

    secret = pyotp.random_base32()

    # Save secret to user but don't enable yet
    user_repo = UserRepository(db)
    await user_repo.update(current_user.id, {"totp_secret": secret})

    # Generate QR Code
    totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=current_user.email, issuer_name=settings.PROJECT_NAME
    )

    img = qrcode.make(totp_uri)
    buffered = io.BytesIO()
    img.save(buffered)
    qr_code_base64 = base64.b64encode(buffered.getvalue()).decode("utf-8")

    return {"secret": secret, "qr_code": qr_code_base64}


@router.post("/me/2fa/enable", response_model=UserSchema)
async def enable_2fa(
    verify_in: User2FAVerify,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    Verify OTP and enable 2FA.
    """
    # User must be either in 2FA setup mode or be a fully active user
    if not is_2fa_setup_mode(current_user) and not current_user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")

    user = await get_user_or_404(current_user.id, db)

    if not security.verify_password(verify_in.password, user["hashed_password"]):
        raise HTTPException(status_code=400, detail="Invalid password")

    secret = user.get("totp_secret")

    if not secret:
        raise HTTPException(status_code=400, detail="2FA setup not initiated")

    totp = pyotp.TOTP(secret)
    if not totp.verify(verify_in.code, valid_window=1):
        raise HTTPException(status_code=400, detail="Invalid OTP code")

    user_repo = UserRepository(db)
    await user_repo.update(current_user.id, {"totp_enabled": True})

    # Send notification if SMTP is configured
    if settings.SMTP_HOST:
        background_tasks.add_task(
            notification_service.email_provider.send,
            destination=current_user.email,
            subject="Security Alert: 2FA Enabled",
            message=(
                f"Hello {current_user.username},\n\nTwo-Factor Authentication (2FA) "
                "has been enabled for your account.\n\nIf you did not initiate this change, "
                "please contact your administrator immediately."
            ),
            html_message=templates.get_2fa_enabled_template(
                username=current_user.username, project_name=settings.PROJECT_NAME
            ),
        )

    return await fetch_updated_user(current_user.id, db)


@router.post("/me/2fa/disable", response_model=UserSchema)
async def disable_2fa(
    disable_in: User2FADisable,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    Disable 2FA.
    """
    user = await get_user_or_404(current_user.id, db)

    if not user.get("totp_enabled"):
        raise HTTPException(
            status_code=400, detail="2FA is not enabled for your account"
        )

    if not security.verify_password(disable_in.password, user["hashed_password"]):
        raise HTTPException(status_code=400, detail="Invalid password")

    user_repo = UserRepository(db)
    await user_repo.update(
        current_user.id, {"totp_enabled": False, "totp_secret": None}
    )

    # Send notification if SMTP is configured
    if settings.SMTP_HOST:
        background_tasks.add_task(
            notification_service.email_provider.send,
            destination=current_user.email,
            subject="Security Alert: 2FA Disabled",
            message=(
                f"Hello {current_user.username},\n\nTwo-Factor Authentication (2FA) "
                "has been disabled for your account.\n\nIf you did not initiate this change, "
                "please contact your administrator immediately."
            ),
            html_message=templates.get_2fa_disabled_template(
                username=current_user.username, project_name=settings.PROJECT_NAME
            ),
        )

    return await fetch_updated_user(current_user.id, db)


@router.post("/{user_id}/2fa/disable", response_model=UserSchema)
async def admin_disable_2fa(
    user_id: str,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(
        deps.PermissionChecker(["user:manage", "user:update"])
    ),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    Admin only: Disable 2FA for a user (e.g. lost device).
    """
    user = await get_user_or_404(user_id, db)

    if not user.get("totp_enabled"):
        raise HTTPException(status_code=400, detail="2FA is not enabled for this user")

    user_repo = UserRepository(db)
    await user_repo.update(user_id, {"totp_enabled": False, "totp_secret": None})

    # Send notification
    if settings.SMTP_HOST:
        try:
            background_tasks.add_task(
                notification_service.email_provider.send,
                destination=user["email"],
                subject="Security Alert: 2FA Disabled by Admin",
                message=(
                    f"Hello {user['username']},\n\nTwo-Factor Authentication (2FA) "
                    "has been disabled for your account by an administrator.\n\n"
                    "If you did not request this, please contact your administrator immediately."
                ),
                html_message=templates.get_2fa_disabled_template(
                    username=user["username"], project_name=settings.PROJECT_NAME
                ),
            )
        except Exception as e:
            logger.error(f"Failed to send 2FA disable email: {e}")

    return await fetch_updated_user(user_id, db)


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(
    user_id: str,
    current_user: User = Depends(
        deps.PermissionChecker(["user:manage", "user:delete"])
    ),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    Delete a user or revoke a pending invitation.
    Requires 'user:manage' or 'user:delete' permissions.
    """
    if user_id == str(current_user.id):
        raise HTTPException(status_code=400, detail="Users cannot delete themselves")

    user_repo = UserRepository(db)
    invitation_repo = InvitationRepository(db)

    # 1. Try to find and delete a real user
    user = await user_repo.get_raw_by_id(user_id)
    if user:
        await user_repo.delete(user_id)
        return None

    # 2. If not found, try to find and delete a pending invitation
    # Invitations use their _id as the user_id in the frontend list
    invitation = await invitation_repo.get_system_invitation(user_id)
    if invitation:
        await invitation_repo.delete_system_invitation(user_id)
        return None

    # 3. If neither found, return 404
    raise HTTPException(status_code=404, detail="User or invitation not found")
