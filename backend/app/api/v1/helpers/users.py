"""
User Helper Functions

Shared utilities for user-related operations.
"""

from typing import Any, Dict

from fastapi import HTTPException
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.core.permissions import has_permission
from app.models.user import User
from app.repositories import UserRepository


async def get_user_or_404(user_id: str, db: AsyncIOMotorDatabase) -> Dict[str, Any]:
    """
    Fetch a user by ID or raise 404.

    Args:
        user_id: The user ID to fetch
        db: Database instance

    Returns:
        Raw user document

    Raises:
        HTTPException: 404 if user not found
    """
    user_repo = UserRepository(db)
    user = await user_repo.get_raw_by_id(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


async def fetch_updated_user(user_id: str, db: AsyncIOMotorDatabase) -> Dict[str, Any]:
    """
    Fetch an updated user after modification.

    Args:
        user_id: The user ID to fetch
        db: Database instance

    Returns:
        Raw user document

    Raises:
        HTTPException: 500 if user retrieval fails
    """
    user_repo = UserRepository(db)
    user = await user_repo.get_raw_by_id(user_id)
    if not user:
        raise HTTPException(status_code=500, detail="Failed to retrieve updated user")
    return user


def check_admin_or_self(
    current_user: User,
    target_user_id: str,
    permissions: list[str],
) -> bool:
    """
    Check if current user has admin permissions or is the target user.

    Args:
        current_user: The current authenticated user
        target_user_id: The target user ID
        permissions: List of admin permissions to check

    Returns:
        True if user has admin permission

    Raises:
        HTTPException: 403 if not admin and not self
    """
    has_admin_perm = has_permission(current_user.permissions, permissions)
    if not has_admin_perm and str(current_user.id) != target_user_id:
        raise HTTPException(status_code=403, detail="Not enough permissions")
    return has_admin_perm


def is_2fa_setup_mode(user: User) -> bool:
    """
    Check if user is in 2FA setup mode.

    Users in 2FA setup mode have only the 'auth:setup_2fa' permission.
    This state occurs when 2FA is enforced and the user must complete
    2FA setup before gaining full access.

    Args:
        user: The user to check

    Returns:
        True if user is in 2FA setup mode
    """
    return "auth:setup_2fa" in user.permissions and len(user.permissions) == 1
