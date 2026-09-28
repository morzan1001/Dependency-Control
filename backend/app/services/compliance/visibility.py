"""Which compliance reports a user may see."""

from typing import Any

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.core.permissions import Permissions, has_permission
from app.models.user import User
from app.repositories.teams import TeamRepository
from app.services.analytics.scopes import ScopeResolver


async def report_visibility_filter(db: AsyncIOMotorDatabase, user: User) -> dict[str, Any]:
    """Own user-scoped reports (every one for system:manage), the readable projects', the own teams', and
    global ones with analytics:global."""
    is_super = has_permission(user.permissions, Permissions.SYSTEM_MANAGE)
    user_id = str(user.id)
    branches: list[dict[str, Any]] = [{"scope": "user"} if is_super else {"scope": "user", "requested_by": user_id}]
    project_ids = [p.id for p in await ScopeResolver(db, user).list_user_projects()]
    if project_ids:
        branches.append({"scope": "project", "scope_id": {"$in": project_ids}})
    team_ids = await TeamRepository(db).find_ids_by_member(user_id)
    if team_ids:
        branches.append({"scope": "team", "scope_id": {"$in": team_ids}})
    if is_super or has_permission(user.permissions, Permissions.ANALYTICS_GLOBAL):
        branches.append({"scope": "global"})
    return {"$or": branches}
