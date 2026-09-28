"""Shared utilities for user-related operations."""

from typing import Any

from fastapi import HTTPException
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.core.permissions import Permissions, has_permission
from app.models.user import User
from app.repositories import UserRepository


async def get_user_or_404(user_id: str, db: AsyncIOMotorDatabase) -> dict[str, Any]:
    """Fetch a raw user document by ID, raising 404 if not found."""
    user_repo = UserRepository(db)
    user = await user_repo.get_raw_by_id(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


async def fetch_updated_user(user_id: str, db: AsyncIOMotorDatabase) -> dict[str, Any]:
    """Fetch a raw user document by ID after modification, raising 500 if retrieval fails."""
    user_repo = UserRepository(db)
    user = await user_repo.get_raw_by_id(user_id)
    if not user:
        raise HTTPException(status_code=500, detail="Failed to retrieve updated user")
    return user


def check_admin_or_self(current_user: User, target_user_id: str, permissions: list[str]) -> None:
    """Raise 403 unless the current user holds one of ``permissions`` or is the target user."""
    if not has_permission(current_user.permissions, permissions) and str(current_user.id) != target_user_id:
        raise HTTPException(status_code=403, detail="Not enough permissions")


def ensure_can_manage_target(caller: User, target: dict[str, Any]) -> None:
    """Raise 403 unless the caller holds every permission of the target account or holds system:manage."""
    if has_permission(caller.permissions, Permissions.SYSTEM_MANAGE):
        return
    if not set(target.get("permissions") or []) <= set(caller.permissions):
        raise HTTPException(status_code=403, detail="Cannot manage a user who holds permissions you don't hold")


def is_2fa_setup_mode(user: User) -> bool:
    """True if the user holds only 'auth:setup_2fa' (must finish 2FA setup for full access)."""
    return "auth:setup_2fa" in user.permissions and len(user.permissions) == 1
