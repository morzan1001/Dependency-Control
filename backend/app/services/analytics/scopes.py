"""
Scope resolution for analytics queries.

Translates a (scope, scope_id) pair into a ResolvedScope that carries the
set of project_ids the caller is authorised to query.  Permission gating is
enforced here so that individual query functions stay scope-agnostic.
"""

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, List, Literal, Optional

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.core.constants import PERMISSION_ANALYTICS_GLOBAL

if TYPE_CHECKING:
    from app.models.user import User

Scope = Literal["project", "team", "global", "user"]


class ScopeResolutionError(PermissionError):
    """Raised when the caller is not allowed to query the requested scope."""


@dataclass
class ResolvedScope:
    scope: Scope
    scope_id: Optional[str]
    project_ids: Optional[List[str]]


class ScopeResolver:
    SYSTEM_MANAGE = "system:manage"

    def __init__(self, db: AsyncIOMotorDatabase, user: "User | Any") -> None:
        self.db = db
        self.user = user

    async def resolve(self, *, scope: Scope, scope_id: Optional[str]) -> ResolvedScope:
        if scope == "project":
            return await self._resolve_project(scope_id)
        if scope == "team":
            return await self._resolve_team(scope_id)
        if scope == "global":
            return self._resolve_global()
        if scope == "user":
            return await self._resolve_user()
        raise ScopeResolutionError(f"Unknown scope: {scope!r}")

    async def _resolve_project(self, scope_id: Optional[str]) -> ResolvedScope:
        if not scope_id:
            raise ScopeResolutionError("project scope requires scope_id")
        if not await self._check_project_member(scope_id):
            raise ScopeResolutionError(f"User not authorised for project {scope_id}")
        return ResolvedScope(scope="project", scope_id=scope_id, project_ids=[scope_id])

    async def _resolve_team(self, scope_id: Optional[str]) -> ResolvedScope:
        if not scope_id:
            raise ScopeResolutionError("team scope requires scope_id")
        if not await self._check_team_member(scope_id):
            raise ScopeResolutionError(f"User not authorised for team {scope_id}")
        project_ids = await self._list_team_project_ids(scope_id)
        return ResolvedScope(scope="team", scope_id=scope_id, project_ids=project_ids)

    def _resolve_global(self) -> ResolvedScope:
        perms: frozenset[str] = getattr(self.user, "permissions", frozenset()) or frozenset()
        if PERMISSION_ANALYTICS_GLOBAL not in perms and self.SYSTEM_MANAGE not in perms:
            raise ScopeResolutionError("Global analytics requires analytics:global or system:manage")
        return ResolvedScope(scope="global", scope_id=None, project_ids=None)

    async def _resolve_user(self) -> ResolvedScope:
        project_ids = await self._list_user_project_ids()
        return ResolvedScope(scope="user", scope_id=None, project_ids=project_ids)

    async def _check_project_member(self, project_id: str) -> bool:
        from app.api.v1.helpers.projects import check_project_access

        try:
            await check_project_access(project_id, self.user, self.db, required_role="viewer")
            return True
        except Exception:
            return False

    async def _check_team_member(self, team_id: str) -> bool:
        from app.repositories.teams import TeamRepository

        team = await TeamRepository(self.db).get_by_id(team_id)
        if team is None:
            return False
        members = getattr(team, "members", [])
        return any(getattr(m, "user_id", None) == self.user.id for m in members)

    async def _list_team_project_ids(self, team_id: str) -> List[str]:
        from app.repositories.projects import ProjectRepository

        projects = await ProjectRepository(self.db).find_many_minimal(
            {"team_id": team_id}, limit=1000
        )
        return [str(p.id) for p in projects]

    async def _list_user_project_ids(self) -> List[str]:
        """Return all project IDs the current user has any access to."""
        from app.repositories.teams import TeamRepository

        team_repo = TeamRepository(self.db)
        user_teams = await team_repo.find_by_member(str(self.user.id))
        team_ids = [t.id for t in user_teams]

        query: dict = {
            "$or": [
                {"members.user_id": str(self.user.id)},
                {"team_id": {"$in": team_ids}},
            ]
        }
        cursor = self.db.projects.find(query, {"_id": 1}).limit(10000)
        docs = await cursor.to_list(length=10000)
        return [str(d["_id"]) for d in docs]
