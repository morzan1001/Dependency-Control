from collections.abc import Sequence
from typing import Any

from fastapi import HTTPException
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.core.permissions import Permissions, has_permission
from app.models.user import User
from app.repositories.users import UserRepository


async def resolve_usernames(
    db: AsyncIOMotorDatabase, rows: Sequence[dict[str, Any]], field: str, id_field: str | None = None
) -> list[dict[str, Any]]:
    id_field = id_field or field
    names = await UserRepository(db).usernames_by_id(row[id_field] for row in rows if row.get(id_field))
    return [{**row, field: names[row[id_field]]} if row.get(id_field) in names else row for row in rows]


async def get_user_or_404(user_id: str, db: AsyncIOMotorDatabase) -> dict[str, Any]:
    user_repo = UserRepository(db)
    user = await user_repo.get_raw_by_id(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


def check_admin_or_self(current_user: User, target_user_id: str, permissions: list[str]) -> None:
    if not has_permission(current_user.permissions, permissions) and str(current_user.id) != target_user_id:
        raise HTTPException(status_code=403, detail="Not enough permissions")


def ensure_can_manage_target(caller: User, target: dict[str, Any]) -> None:
    if has_permission(caller.permissions, Permissions.SYSTEM_MANAGE):
        return
    if not set(target.get("permissions") or []) <= set(caller.permissions):
        raise HTTPException(status_code=403, detail="Cannot manage a user who holds permissions you don't hold")
