"""Which compliance reports a user may see."""

from typing import Any

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.api.v1.helpers.projects import build_user_project_query
from app.core.constants import ScopeName
from app.core.permissions import Permissions, has_permission
from app.models.user import User
from app.repositories.teams import TeamRepository
from app.services.analytics.scopes import may_query_global, read_scope_projects, team_scope_filter


async def report_visibility_filter(
    db: AsyncIOMotorDatabase, user: User, scope: ScopeName | None = None
) -> dict[str, Any]:
    """Own user reports (all for system:manage) plus project, team and global reports whose scope resolves."""
    is_super = has_permission(user.permissions, Permissions.SYSTEM_MANAGE)
    branches: list[dict[str, Any]] = [
        {"scope": "user"} if is_super else {"scope": "user", "requested_by": str(user.id)}
    ]
    team_repo = TeamRepository(db)
    if scope in (None, "project"):
        project_query = await build_user_project_query(user, team_repo)
        if not project_query:
            branches.append({"scope": "project"})
        elif project_ids := [p.id for p in await read_scope_projects(db, project_query)]:
            branches.append({"scope": "project", "scope_id": {"$in": project_ids}})
    teams = team_scope_filter(user) if scope in (None, "team") else None
    team_ids = [] if teams is None else await team_repo.find_ids(teams)
    if team_ids:
        branches.append({"scope": "team", "scope_id": {"$in": team_ids}})
    if may_query_global(user):
        branches.append({"scope": "global"})
    return {"$or": branches}
