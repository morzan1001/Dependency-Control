"""Which compliance reports a user may see."""

from typing import Any

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.core.permissions import Permissions, has_permission
from app.models.user import User
from app.repositories.teams import TeamRepository
from app.services.analytics.scopes import ScopeResolver, may_query_global, team_scope_filter


async def report_visibility_filter(db: AsyncIOMotorDatabase, user: User) -> dict[str, Any]:
    """Own user reports (all for system:manage) and the project, team and global reports whose scope resolves."""
    is_super = has_permission(user.permissions, Permissions.SYSTEM_MANAGE)
    branches: list[dict[str, Any]] = [
        {"scope": "user"} if is_super else {"scope": "user", "requested_by": str(user.id)}
    ]
    project_ids = [p.id for p in await ScopeResolver(db, user).list_user_projects()]
    if project_ids:
        branches.append({"scope": "project", "scope_id": {"$in": project_ids}})
    teams = team_scope_filter(user)
    team_ids = [] if teams is None else await TeamRepository(db).find_ids(teams)
    if team_ids:
        branches.append({"scope": "team", "scope_id": {"$in": team_ids}})
    if may_query_global(user):
        branches.append({"scope": "global"})
    return {"$or": branches}
