import base64
import io
import logging
import re
from typing import Annotated, Any

import pyotp
import qrcode
from fastapi import BackgroundTasks, Depends, HTTPException, status

from app.api import deps
from app.api.deps import CurrentUserDep, DatabaseDep
from app.api.router import CustomAPIRouter
from app.api.v1.helpers import (
    check_admin_or_self,
    ensure_can_manage_target,
    fetch_updated_user,
    get_logo_path,
    get_user_or_404,
    is_2fa_setup_mode,
    send_email_change_email,
    send_password_reset_email,
)
from app.api.v1.helpers.responses import (
    RESP_AUTH,
    RESP_AUTH_400,
    RESP_AUTH_400_404,
    RESP_AUTH_400_404_501,
    RESP_AUTH_400_501,
    RESP_AUTH_404,
)
from app.core import security
from app.core.config import settings
from app.core.constants import AUTH_PROVIDER_LOCAL
from app.core.permissions import Permissions, has_permission
from app.models.user import User
from app.repositories.invitations import InvitationRepository
from app.repositories.users import UserRepository
from app.schemas.user import User as UserSchema
from app.schemas.user import (
    User2FADisable,
    User2FASetup,
    User2FAVerify,
    UserCreate,
    UserEmailChange,
    UserMigrateToLocal,
    UserPasswordUpdate,
    UserUpdate,
    UserUpdateMe,
)
from app.services.notifications import templates
from app.services.notifications.service import notification_service

router = CustomAPIRouter()
logger = logging.getLogger(__name__)


@router.post("/", response_model=UserSchema, status_code=status.HTTP_201_CREATED, responses=RESP_AUTH_400)
async def create_user(
    user_in: UserCreate,
    current_user: Annotated[User, Depends(deps.PermissionChecker([Permissions.USER_CREATE]))],
    db: DatabaseDep,
) -> User:
    """Create a new user. Requires 'user:create' permission."""
    if not user_in.password:
        raise HTTPException(
            status_code=400,
            detail="Password is required when creating a user",
        )

    # A caller may never grant a permission they don't hold themselves.
    if user_in.permissions:
        if not has_permission(current_user.permissions, [Permissions.USER_MANAGE_PERMISSIONS]):
            raise HTTPException(
                status_code=403,
                detail="Setting 'permissions' requires user:manage_permissions",
            )
        caller_perms = set(current_user.permissions or [])
        requested = set(user_in.permissions or [])
        unauthorised = requested - caller_perms
        if unauthorised:
            raise HTTPException(
                status_code=403,
                detail=f"Cannot grant permissions you don't hold: {sorted(unauthorised)}",
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


@router.get("/", response_model=list[UserSchema], responses=RESP_AUTH)
async def read_users(
    current_user: Annotated[User, Depends(deps.PermissionChecker([Permissions.USER_READ_ALL]))],
    db: DatabaseDep,
    skip: int = 0,
    limit: int = 100,
    search: str | None = None,
    sort_by: str = "username",
    sort_order: str = "asc",
) -> list[User]:
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
    return await user_repo.find_many(query, skip=skip, limit=limit, sort_by=sort_by, sort_order=sort_direction)


@router.get("/me", response_model=UserSchema, responses=RESP_AUTH)
async def read_user_me(
    current_user: CurrentUserDep,
) -> User:
    """Get current user."""
    return current_user


@router.patch("/me", response_model=UserSchema, responses=RESP_AUTH_400)
async def update_user_me(
    user_in: UserUpdateMe,
    current_user: CurrentUserDep,
    db: DatabaseDep,
) -> dict[str, Any]:
    """Update own profile."""
    update_data = user_in.model_dump(exclude_unset=True)

    if update_data:
        await UserRepository(db).update(current_user.id, update_data)

    return await fetch_updated_user(current_user.id, db)


@router.post("/me/email", response_model=UserSchema, responses=RESP_AUTH_400_501)
async def request_email_change(
    email_in: UserEmailChange,
    background_tasks: BackgroundTasks,
    current_user: CurrentUserDep,
    db: DatabaseDep,
) -> dict[str, Any]:
    """Park a new email as pending and mail it a confirmation link (local accounts only)."""
    if current_user.auth_provider != AUTH_PROVIDER_LOCAL:
        raise HTTPException(status_code=400, detail="Your email is managed by your identity provider")

    system_settings = await deps.get_system_settings(db)
    if not system_settings.smtp_host:
        raise HTTPException(status_code=status.HTTP_501_NOT_IMPLEMENTED, detail="Email server not configured")

    if email_in.email == current_user.email.lower():
        raise HTTPException(status_code=400, detail="This is already your email address")

    user_repo = UserRepository(db)
    if await user_repo.exists_by_email(email_in.email):
        raise HTTPException(status_code=400, detail="Email already registered")

    await user_repo.update(current_user.id, {"pending_email": email_in.email})
    send_email_change_email(background_tasks, current_user.id, email_in.email, system_settings)

    return await fetch_updated_user(current_user.id, db)


@router.get("/{user_id}", response_model=UserSchema, responses=RESP_AUTH_404)
async def read_user_by_id(
    user_id: str,
    current_user: CurrentUserDep,
    db: DatabaseDep,
) -> dict[str, Any]:
    """Get user by ID. Requires admin permission or self."""
    check_admin_or_self(current_user, user_id, [Permissions.USER_READ])
    return await get_user_or_404(user_id, db)


def _ensure_can_change_permissions(caller: User, existing: set[str], requested: set[str]) -> None:
    """Require user:manage_permissions and refuse to grant or revoke any permission the caller lacks."""
    if not has_permission(caller.permissions, [Permissions.USER_MANAGE_PERMISSIONS]):
        raise HTTPException(
            status_code=403,
            detail="Changing 'permissions' requires user:manage_permissions",
        )
    caller_perms = set(caller.permissions or [])
    unauthorised_grants = requested - existing - caller_perms
    if unauthorised_grants:
        raise HTTPException(
            status_code=403,
            detail=f"Cannot grant permissions you don't hold: {sorted(unauthorised_grants)}",
        )
    unauthorised_revokes = existing - requested - caller_perms
    if unauthorised_revokes:
        raise HTTPException(
            status_code=403,
            detail=f"Cannot revoke permissions you don't hold: {sorted(unauthorised_revokes)}",
        )


async def _ensure_admin_can_set_email(user_repo: UserRepository, target: dict[str, Any], new_email: str) -> None:
    """The IdP owns a non-local account's email; any other address must be unused in every case."""
    if target.get("auth_provider", AUTH_PROVIDER_LOCAL) != AUTH_PROVIDER_LOCAL:
        raise HTTPException(status_code=400, detail="This account's email is managed by its identity provider")
    if await user_repo.exists_by_email(new_email):
        raise HTTPException(status_code=400, detail="Email already registered")


@router.put("/{user_id}", response_model=UserSchema, responses=RESP_AUTH_400_404)
async def update_user(
    user_id: str,
    user_in: UserUpdate,
    current_user: CurrentUserDep,
    db: DatabaseDep,
) -> dict[str, Any]:
    """Update self, or as an admin a user whose permissions the caller holds (or any user with system:manage)."""
    has_admin_perm = check_admin_or_self(current_user, user_id, [Permissions.USER_UPDATE])
    is_self = str(current_user.id) == user_id

    existing_user = await get_user_or_404(user_id, db)
    if not is_self:
        ensure_can_manage_target(current_user, existing_user)

    user_repo = UserRepository(db)
    update_data = user_in.model_dump(exclude_unset=True)

    if is_self and update_data.keys() & {"username", "email"}:
        raise HTTPException(
            status_code=403,
            detail="Change your email from your profile; only an administrator can change your username",
        )

    if "permissions" in update_data:
        _ensure_can_change_permissions(
            current_user,
            existing=set(existing_user.get("permissions") or []),
            requested=set(update_data["permissions"] or []),
        )

    # Forbid self-change of is_active so a user can't lock themselves or every admin out.
    if "is_active" in update_data and is_self:
        raise HTTPException(
            status_code=403,
            detail="Cannot change your own active state",
        )

    if "email" in update_data and update_data["email"] != existing_user["email"].lower():
        await _ensure_admin_can_set_email(user_repo, existing_user, update_data["email"])
        update_data["is_verified"] = False

    if (
        "username" in update_data
        and update_data["username"] != existing_user.get("username")
        and await user_repo.exists_by_username(update_data["username"])
    ):
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
        raise HTTPException(
            status_code=400,
            detail="Use the /me/password endpoint to change your password.",
        )

    if update_data:
        await user_repo.update(user_id, update_data)

    return await fetch_updated_user(user_id, db)


@router.post("/me/migrate", response_model=UserSchema, responses=RESP_AUTH_400)
async def migrate_to_local(
    *,
    password_in: UserMigrateToLocal,
    current_user: CurrentUserDep,
    db: DatabaseDep,
) -> dict[str, Any]:
    """Migrate SSO user to local account by setting a password."""
    if current_user.auth_provider == AUTH_PROVIDER_LOCAL:
        raise HTTPException(status_code=400, detail="User is already a local account.")

    hashed_password = security.get_password_hash(password_in.new_password)

    user_repo = UserRepository(db)
    await user_repo.update(
        current_user.id,
        {"hashed_password": hashed_password, "auth_provider": AUTH_PROVIDER_LOCAL},
    )

    return await fetch_updated_user(current_user.id, db)


@router.post("/{user_id}/migrate", response_model=UserSchema, responses=RESP_AUTH_400_404)
async def migrate_user_to_local(
    user_id: str,
    current_user: Annotated[User, Depends(deps.PermissionChecker([Permissions.USER_UPDATE]))],
    db: DatabaseDep,
) -> dict[str, Any]:
    """Admin only: switch a user's auth_provider to 'local' without setting a password (follow with a reset)."""
    user = await get_user_or_404(user_id, db)
    ensure_can_manage_target(current_user, user)

    if user.get("auth_provider") == AUTH_PROVIDER_LOCAL:
        raise HTTPException(status_code=400, detail="User is already a local account")

    user_repo = UserRepository(db)
    await user_repo.update(user_id, {"auth_provider": AUTH_PROVIDER_LOCAL})

    return await fetch_updated_user(user_id, db)


@router.post("/{user_id}/reset-password", responses=RESP_AUTH_400_404_501)
async def reset_user_password(
    user_id: str,
    background_tasks: BackgroundTasks,
    current_user: Annotated[User, Depends(deps.PermissionChecker([Permissions.USER_UPDATE]))],
    db: DatabaseDep,
) -> dict[str, str]:
    """Admin only: email the user a password reset link; the link is never returned to the caller."""
    user = await get_user_or_404(user_id, db)
    ensure_can_manage_target(current_user, user)

    if user.get("auth_provider", AUTH_PROVIDER_LOCAL) != AUTH_PROVIDER_LOCAL:
        raise HTTPException(
            status_code=400,
            detail="Cannot reset password for non-local users. Please migrate user first.",
        )

    system_settings = await deps.get_system_settings(db)
    if not system_settings.smtp_host:
        raise HTTPException(status_code=status.HTTP_501_NOT_IMPLEMENTED, detail="Email server not configured")

    await send_password_reset_email(background_tasks, user["email"], user["username"], system_settings=system_settings)
    return {"message": "Password reset email sent"}


@router.post("/me/password", response_model=UserSchema, responses=RESP_AUTH_400)
async def update_password_me(
    password_in: UserPasswordUpdate,
    background_tasks: BackgroundTasks,
    current_user: CurrentUserDep,
    db: DatabaseDep,
) -> dict[str, Any]:
    """Update current user password."""
    if current_user.auth_provider != AUTH_PROVIDER_LOCAL:
        raise HTTPException(
            status_code=400,
            detail="SSO users cannot change password. Please migrate to local account first.",
        )

    if not security.verify_password(password_in.current_password, current_user.hashed_password):
        raise HTTPException(status_code=400, detail="Incorrect password")

    hashed_password = security.get_password_hash(password_in.new_password)

    user_repo = UserRepository(db)
    await user_repo.update(current_user.id, {"hashed_password": hashed_password})

    if settings.SMTP_HOST:
        system_settings = await deps.get_system_settings(db)
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
            logo_path=get_logo_path(),
            system_settings=system_settings,
        )

    return await fetch_updated_user(current_user.id, db)


@router.post("/me/2fa/setup", response_model=User2FASetup, responses=RESP_AUTH_400)
async def setup_2fa(
    current_user: CurrentUserDep,
    db: DatabaseDep,
) -> dict[str, str]:
    """Generate a new 2FA secret and QR code (local auth users only)."""
    if current_user.auth_provider and current_user.auth_provider != "local":
        raise HTTPException(
            status_code=400,
            detail="2FA must be configured in your identity provider, not in this application",
        )

    if not is_2fa_setup_mode(current_user) and not current_user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")

    secret = pyotp.random_base32()

    # Store the secret but leave 2FA disabled until verified.
    user_repo = UserRepository(db)
    await user_repo.update(current_user.id, {"totp_secret": secret})

    totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(name=current_user.email, issuer_name=settings.PROJECT_NAME)

    img = qrcode.make(totp_uri)
    buffered = io.BytesIO()
    img.save(buffered)
    qr_code_base64 = base64.b64encode(buffered.getvalue()).decode("utf-8")

    return {"secret": secret, "qr_code": qr_code_base64}


@router.post("/me/2fa/enable", response_model=UserSchema, responses=RESP_AUTH_400)
async def enable_2fa(
    verify_in: User2FAVerify,
    background_tasks: BackgroundTasks,
    current_user: CurrentUserDep,
    db: DatabaseDep,
) -> dict[str, Any]:
    """Verify OTP and enable 2FA (local auth users only)."""
    if current_user.auth_provider and current_user.auth_provider != "local":
        raise HTTPException(
            status_code=400,
            detail="2FA must be configured in your identity provider, not in this application",
        )

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

    if settings.SMTP_HOST:
        system_settings = await deps.get_system_settings(db)
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
            logo_path=get_logo_path(),
            system_settings=system_settings,
        )

    return await fetch_updated_user(current_user.id, db)


@router.post("/me/2fa/disable", response_model=UserSchema, responses=RESP_AUTH_400)
async def disable_2fa(
    disable_in: User2FADisable,
    background_tasks: BackgroundTasks,
    current_user: CurrentUserDep,
    db: DatabaseDep,
) -> dict[str, Any]:
    """Disable 2FA."""
    user = await get_user_or_404(current_user.id, db)

    if not user.get("totp_enabled"):
        raise HTTPException(status_code=400, detail="2FA is not enabled for your account")

    if not security.verify_password(disable_in.password, user["hashed_password"]):
        raise HTTPException(status_code=400, detail="Invalid password")

    user_repo = UserRepository(db)
    await user_repo.update(current_user.id, {"totp_enabled": False, "totp_secret": None})

    if settings.SMTP_HOST:
        system_settings = await deps.get_system_settings(db)
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
            logo_path=get_logo_path(),
            system_settings=system_settings,
        )

    return await fetch_updated_user(current_user.id, db)


@router.post("/{user_id}/2fa/disable", response_model=UserSchema, responses=RESP_AUTH_400_404)
async def admin_disable_2fa(
    user_id: str,
    background_tasks: BackgroundTasks,
    current_user: Annotated[User, Depends(deps.PermissionChecker([Permissions.USER_UPDATE]))],
    db: DatabaseDep,
) -> dict[str, Any]:
    """Admin only: disable 2FA for a user (e.g. lost device)."""
    user = await get_user_or_404(user_id, db)
    ensure_can_manage_target(current_user, user)

    if not user.get("totp_enabled"):
        raise HTTPException(status_code=400, detail="2FA is not enabled for this user")

    user_repo = UserRepository(db)
    await user_repo.update(user_id, {"totp_enabled": False, "totp_secret": None})

    if settings.SMTP_HOST:
        try:
            system_settings = await deps.get_system_settings(db)
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
                logo_path=get_logo_path(),
                system_settings=system_settings,
            )
        except Exception as e:
            logger.exception("Failed to send 2FA disable email: %s", e)

    return await fetch_updated_user(user_id, db)


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT, responses=RESP_AUTH_400_404)
async def delete_user(
    user_id: str,
    current_user: Annotated[User, Depends(deps.PermissionChecker([Permissions.USER_DELETE]))],
    db: DatabaseDep,
) -> None:
    """Delete a user or revoke a pending invitation. Requires 'user:delete' permission."""
    if user_id == str(current_user.id):
        raise HTTPException(status_code=400, detail="Users cannot delete themselves")

    user_repo = UserRepository(db)
    invitation_repo = InvitationRepository(db)

    user = await user_repo.get_raw_by_id(user_id)
    if user:
        ensure_can_manage_target(current_user, user)
        await user_repo.delete(user_id)
        return

    # Pending invitations use their _id as the user_id in the frontend list.
    invitation = await invitation_repo.get_system_invitation(user_id)
    if invitation:
        await invitation_repo.delete_system_invitation(user_id)
        return

    raise HTTPException(status_code=404, detail="User or invitation not found")
