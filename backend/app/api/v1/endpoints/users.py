import asyncio
import base64
import io
import logging
import re
from datetime import datetime, timezone
from typing import Annotated, Any

import pyotp
import qrcode
from fastapi import BackgroundTasks, Depends, HTTPException, Query, status

from app.api import deps
from app.api.deps import CurrentUserDep, DatabaseDep
from app.api.router import CustomAPIRouter
from app.api.v1.helpers import (
    check_admin_or_self,
    ensure_can_manage_target,
    get_user_or_404,
)
from app.api.v1.helpers.auth import (
    require_email_configured,
    send_2fa_disabled_email,
    send_2fa_enabled_email,
    send_email_change_email,
    send_password_changed_email,
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
from app.api.v1.helpers.sorting import CASE_INSENSITIVE, SortOrderQuery, parse_sort_direction
from app.core import security
from app.core.constants import AUTH_PROVIDER_LOCAL
from app.core.permissions import Permissions, has_permission
from app.models.user import User, is_local_account
from app.repositories.projects import ProjectRepository
from app.repositories.teams import TeamRepository
from app.repositories.users import IdentityTakenError, UserRepository
from app.schemas.user import UserResponse
from app.schemas.user import (
    EmailChangeResponse,
    User2FADisable,
    User2FASetup,
    User2FAVerify,
    UserCreate,
    UserEmailChange,
    UserMigrateToLocal,
    UserPasswordUpdate,
    UserUpdate,
    UserUpdateMe,
    check_new_username,
)

router = CustomAPIRouter()
logger = logging.getLogger(__name__)


async def _update_or_404(user_repo: UserRepository, user_id: str, update_data: dict[str, Any]) -> User:
    user = await user_repo.update(user_id, update_data)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return user


async def _save_user_fields(
    user_repo: UserRepository, actor: User, target_id: str, current_name: str, update_data: dict[str, Any]
) -> User:
    new_name: str | None = update_data.get("username")
    if new_name == current_name:
        del update_data["username"]
        new_name = None
    elif new_name is not None:
        try:
            check_new_username(new_name)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        await user_repo.ensure_username_free(new_name, except_id=target_id)

    updated = await _update_or_404(user_repo, target_id, update_data)
    if new_name is not None:
        logger.info("User %s renamed user %s from %r to %r", actor.id, target_id, current_name, new_name)
    return updated


def _ensure_can_set_permissions(caller: User, existing: set[str], requested: set[str]) -> None:
    if not has_permission(caller.permissions, [Permissions.USER_MANAGE_PERMISSIONS]):
        raise HTTPException(
            status_code=403,
            detail="Setting 'permissions' requires user:manage_permissions",
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


@router.post("/", response_model=UserResponse, status_code=status.HTTP_201_CREATED, responses=RESP_AUTH_400)
async def create_user(
    user_in: UserCreate,
    current_user: Annotated[User, Depends(deps.PermissionChecker([Permissions.USER_CREATE]))],
    db: DatabaseDep,
) -> User:
    """Create a new user. Requires 'user:create' permission."""
    if user_in.permissions:
        _ensure_can_set_permissions(current_user, existing=set(), requested=set(user_in.permissions))

    user_dict = user_in.model_dump()
    user_dict["hashed_password"] = security.get_password_hash(user_dict.pop("password"))

    # The admin vouches for the address, as an accepted invitation does.
    new_user = User(**user_dict, is_verified=True)
    user_repo = UserRepository(db)
    await user_repo.ensure_username_free(new_user.username)
    await user_repo.create(new_user)
    return new_user


@router.get("/", response_model=list[UserResponse], responses=RESP_AUTH)
async def read_users(
    current_user: Annotated[User, Depends(deps.PermissionChecker([Permissions.USER_READ_ALL]))],
    db: DatabaseDep,
    skip: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=100)] = 100,
    search: str | None = None,
    sort_by: str = "username",
    sort_order: SortOrderQuery = "asc",
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

    user_repo = UserRepository(db)
    return await user_repo.find_many(
        query,
        skip=skip,
        limit=limit,
        sort_by=sort_by,
        sort_order=parse_sort_direction(sort_order),
        collation=CASE_INSENSITIVE,
    )


@router.get("/me", response_model=UserResponse, responses=RESP_AUTH)
async def read_user_me(
    current_user: CurrentUserDep,
) -> User:
    """Get current user."""
    return current_user


@router.patch("/me", response_model=UserResponse, responses=RESP_AUTH_400)
async def update_user_me(
    user_in: UserUpdateMe,
    current_user: CurrentUserDep,
    db: DatabaseDep,
) -> User:
    """Update own profile."""
    return await _save_user_fields(
        UserRepository(db), current_user, current_user.id, current_user.username, user_in.model_dump(exclude_unset=True)
    )


@router.post("/me/email", response_model=EmailChangeResponse, responses=RESP_AUTH_400_501)
async def change_email(
    email_in: UserEmailChange,
    background_tasks: BackgroundTasks,
    current_user: CurrentUserDep,
    db: DatabaseDep,
) -> dict[str, Any]:
    """Change a local account's email: pending a mailed link, or at once and unverified without a mail server."""
    if not current_user.is_local:
        raise HTTPException(status_code=400, detail="Your email is managed by your identity provider")

    system_settings = await deps.get_system_settings(db)
    if system_settings.enforce_email_verification and not system_settings.email_configured:
        raise HTTPException(
            status_code=501,
            detail="Email verification is required, but no mail server is configured to confirm a new address",
        )

    if email_in.email == current_user.email.lower():
        raise HTTPException(status_code=400, detail="This is already your email address")

    user_repo = UserRepository(db)
    if await user_repo.exists_by_email(email_in.email):
        raise IdentityTakenError("email")

    if system_settings.email_configured:
        updated = await _update_or_404(user_repo, current_user.id, {"pending_email": email_in.email})
        send_email_change_email(background_tasks, current_user.id, email_in.email, system_settings)
        email_change = "pending_confirmation"
    else:
        # Clearing pending_email voids the link of an earlier request.
        updated = await _update_or_404(
            user_repo, current_user.id, {"email": email_in.email, "pending_email": None, "is_verified": False}
        )
        email_change = "changed"

    return {**updated.model_dump(by_alias=True), "email_change": email_change}


@router.get("/{user_id}", response_model=UserResponse, responses=RESP_AUTH_404)
async def read_user_by_id(
    user_id: str,
    current_user: CurrentUserDep,
    db: DatabaseDep,
) -> dict[str, Any]:
    """Get user by ID. Requires admin permission or self."""
    check_admin_or_self(current_user, user_id, [Permissions.USER_READ_ALL])
    return await get_user_or_404(user_id, db)


@router.put("/{user_id}", response_model=UserResponse, responses=RESP_AUTH_400_404)
async def update_user(
    user_id: str,
    user_in: UserUpdate,
    current_user: Annotated[User, Depends(deps.PermissionChecker([Permissions.USER_UPDATE]))],
    db: DatabaseDep,
) -> User:
    """Update a user whose permissions the caller holds (or any user with system:manage)."""
    is_self = str(current_user.id) == user_id

    existing_user = await get_user_or_404(user_id, db)
    ensure_can_manage_target(current_user, existing_user)

    user_repo = UserRepository(db)
    update_data = user_in.model_dump(exclude_unset=True)

    if is_self and "email" in update_data:
        raise HTTPException(status_code=403, detail="Change your email from your profile")

    if "permissions" in update_data:
        _ensure_can_set_permissions(
            current_user,
            existing=set(existing_user.get("permissions") or []),
            requested=set(update_data["permissions"]),
        )

    # Forbid self-change of is_active so a user can't lock themselves or every admin out.
    if "is_active" in update_data and is_self:
        raise HTTPException(
            status_code=403,
            detail="Cannot change your own active state",
        )

    if "email" in update_data and update_data["email"] != existing_user["email"].lower():
        if not is_local_account(existing_user.get("auth_provider")):
            raise HTTPException(status_code=400, detail="This account's email is managed by its identity provider")
        update_data["is_verified"] = False

    return await _save_user_fields(user_repo, current_user, user_id, existing_user["username"], update_data)


@router.post("/me/migrate", response_model=UserResponse, responses=RESP_AUTH_400)
async def migrate_to_local(
    *,
    password_in: UserMigrateToLocal,
    current_user: CurrentUserDep,
    db: DatabaseDep,
) -> User:
    """Migrate SSO user to local account by setting a password."""
    if current_user.is_local:
        raise HTTPException(status_code=400, detail="User is already a local account")

    hashed_password = security.get_password_hash(password_in.new_password)

    return await _update_or_404(
        UserRepository(db), current_user.id, {"hashed_password": hashed_password, "auth_provider": AUTH_PROVIDER_LOCAL}
    )


@router.post("/{user_id}/migrate", response_model=UserResponse, responses=RESP_AUTH_400_404)
async def migrate_user_to_local(
    user_id: str,
    current_user: Annotated[User, Depends(deps.PermissionChecker([Permissions.USER_UPDATE]))],
    db: DatabaseDep,
) -> User:
    """Admin only: switch a user's auth_provider to 'local' without setting a password (follow with a reset)."""
    user = await get_user_or_404(user_id, db)
    ensure_can_manage_target(current_user, user)

    if is_local_account(user.get("auth_provider")):
        raise HTTPException(status_code=400, detail="User is already a local account")

    return await _update_or_404(UserRepository(db), user_id, {"auth_provider": AUTH_PROVIDER_LOCAL})


@router.post("/{user_id}/reset-password", responses=RESP_AUTH_400_404_501)
async def reset_user_password(
    user_id: str,
    background_tasks: BackgroundTasks,
    current_user: Annotated[User, Depends(deps.PermissionChecker([Permissions.USER_UPDATE]))],
    db: DatabaseDep,
) -> dict[str, Any]:
    """Admin only: email the user a password reset link; the link is never returned to the caller."""
    user = await get_user_or_404(user_id, db)
    ensure_can_manage_target(current_user, user)

    if not is_local_account(user.get("auth_provider")):
        raise HTTPException(
            status_code=400,
            detail="Cannot reset password for non-local users. Please migrate user first.",
        )

    system_settings = await deps.get_system_settings(db)
    require_email_configured(system_settings)

    email_queued = send_password_reset_email(background_tasks, user, system_settings)
    return {"message": "Password reset email queued", "email_queued": email_queued}


@router.post("/me/password", response_model=UserResponse, responses=RESP_AUTH_400)
async def update_password_me(
    password_in: UserPasswordUpdate,
    background_tasks: BackgroundTasks,
    current_user: CurrentUserDep,
    db: DatabaseDep,
) -> User:
    """Update current user password."""
    if not current_user.is_local:
        raise HTTPException(
            status_code=400,
            detail="SSO users cannot change password. Please migrate to local account first.",
        )

    if not security.verify_password(password_in.current_password, current_user.hashed_password):
        raise HTTPException(status_code=400, detail="Incorrect password")

    hashed_password = security.get_password_hash(password_in.new_password)

    updated = await _update_or_404(
        UserRepository(db),
        current_user.id,
        {"hashed_password": hashed_password, "last_logout_at": datetime.now(timezone.utc)},
    )

    send_password_changed_email(
        background_tasks, current_user.email, current_user.username, await deps.get_system_settings(db)
    )

    return updated


def _qr_png_base64(uri: str) -> str:
    buffered = io.BytesIO()
    qrcode.make(uri).save(buffered)
    return base64.b64encode(buffered.getvalue()).decode("utf-8")


@router.post("/me/2fa/setup", response_model=User2FASetup, responses=RESP_AUTH_400)
async def setup_2fa(
    current_user: CurrentUserDep,
    db: DatabaseDep,
) -> dict[str, str]:
    """Generate a new 2FA secret and QR code (local auth users only)."""
    if not current_user.is_local:
        raise HTTPException(
            status_code=400,
            detail="2FA must be configured in your identity provider, not in this application",
        )
    if current_user.totp_enabled:
        raise HTTPException(status_code=400, detail="2FA is already enabled; disable it first")

    secret = pyotp.random_base32()

    # Store the secret but leave 2FA disabled until verified.
    user_repo = UserRepository(db)
    await user_repo.update_raw(current_user.id, {"$set": {"totp_secret": secret}, "$unset": {"totp_last_step": ""}})

    issuer = (await deps.get_system_settings(db)).brand
    totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(name=current_user.email, issuer_name=issuer)

    return {"secret": secret, "qr_code": await asyncio.to_thread(_qr_png_base64, totp_uri)}


@router.post("/me/2fa/enable", response_model=UserResponse, responses=RESP_AUTH_400)
async def enable_2fa(
    verify_in: User2FAVerify,
    background_tasks: BackgroundTasks,
    current_user: CurrentUserDep,
    db: DatabaseDep,
) -> User:
    """Verify OTP and enable 2FA (local auth users only)."""
    if not current_user.is_local:
        raise HTTPException(
            status_code=400,
            detail="2FA must be configured in your identity provider, not in this application",
        )

    if not security.verify_password(verify_in.password, current_user.hashed_password):
        raise HTTPException(status_code=400, detail="Invalid password")

    secret = current_user.totp_secret

    if not secret:
        raise HTTPException(status_code=400, detail="2FA setup not initiated")

    step = security.verify_totp(secret, verify_in.code)
    if step is None:
        raise HTTPException(status_code=400, detail="Invalid OTP code")

    updated = await _update_or_404(UserRepository(db), current_user.id, {"totp_enabled": True, "totp_last_step": step})

    send_2fa_enabled_email(
        background_tasks, current_user.email, current_user.username, await deps.get_system_settings(db)
    )

    return updated


@router.post("/me/2fa/disable", response_model=UserResponse, responses=RESP_AUTH_400)
async def disable_2fa(
    disable_in: User2FADisable,
    background_tasks: BackgroundTasks,
    current_user: CurrentUserDep,
    db: DatabaseDep,
) -> dict[str, Any]:
    """Disable 2FA."""
    if not current_user.totp_enabled:
        raise HTTPException(status_code=400, detail="2FA is not enabled for your account")

    if not security.verify_password(disable_in.password, current_user.hashed_password):
        raise HTTPException(status_code=400, detail="Invalid password")

    user_repo = UserRepository(db)
    await user_repo.update_raw(
        current_user.id, {"$set": {"totp_enabled": False, "totp_secret": None}, "$unset": {"totp_last_step": ""}}
    )

    send_2fa_disabled_email(
        background_tasks, current_user.email, current_user.username, await deps.get_system_settings(db), by_admin=False
    )

    return await get_user_or_404(current_user.id, db)


@router.post("/{user_id}/2fa/disable", response_model=UserResponse, responses=RESP_AUTH_400_404)
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
    await user_repo.update_raw(
        user_id, {"$set": {"totp_enabled": False, "totp_secret": None}, "$unset": {"totp_last_step": ""}}
    )

    send_2fa_disabled_email(
        background_tasks, user["email"], user["username"], await deps.get_system_settings(db), by_admin=True
    )

    return await get_user_or_404(user_id, db)


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT, responses=RESP_AUTH_400_404)
async def delete_user(
    user_id: str,
    current_user: Annotated[User, Depends(deps.PermissionChecker([Permissions.USER_DELETE]))],
    db: DatabaseDep,
) -> None:
    """Delete a user and their team and project memberships. Requires 'user:delete' permission."""
    if user_id == str(current_user.id):
        raise HTTPException(status_code=400, detail="Users cannot delete themselves")

    user_repo = UserRepository(db)
    user = await user_repo.get_raw_by_id(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    ensure_can_manage_target(current_user, user)

    # Memberships first: a leftover admin entry would satisfy the last-admin guards for a ghost.
    await TeamRepository(db).remove_user_from_all(user_id, datetime.now(timezone.utc))
    await ProjectRepository(db).remove_user_from_all(user_id)
    await user_repo.delete(user_id)
