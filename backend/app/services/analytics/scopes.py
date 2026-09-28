"""Resolves an analytics (scope, scope_id) into the projects the caller may query, so query functions stay scope-agnostic."""

from dataclasses import dataclass
from typing import Any

from fastapi import HTTPException
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.core.constants import ANALYTICS_MAX_SCOPE_PROJECTS
from app.core.permissions import Permissions, has_permission
from app.models.user import User
from app.repositories.base import and_filters
from app.repositories.projects import ProjectRepository
from app.repositories.teams import TeamRepository
from app.schemas.analytics import ScopeKind
from app.schemas.projections import ProjectWithScanId

_SCOPE_TOO_LARGE = (
    "This scope holds more than {limit} projects. Analytics is answered over a materialised "
    "project list and nothing in the response can name the projects a longer one would drop, "
    "so the request is refused rather than answered over an arbitrary subset. Query a team or "
    "a single project."
)


class ScopeResolutionError(PermissionError):
    """Raised when the caller is not allowed to query the requested scope."""


class ScopeTooLargeError(Exception):
    """Raised when a scope holds more projects than analytics can materialise as one id list."""


async def read_scope_projects(db: AsyncIOMotorDatabase, query: dict[str, Any]) -> list[ProjectWithScanId]:
    """The projects ``query`` selects with the fields head resolution reads, refused past the ceiling."""
    projects = await ProjectRepository(db).find_many_with_scan_id(query, limit=ANALYTICS_MAX_SCOPE_PROJECTS + 1)
    if len(projects) > ANALYTICS_MAX_SCOPE_PROJECTS:
        raise ScopeTooLargeError(_SCOPE_TOO_LARGE.format(limit=ANALYTICS_MAX_SCOPE_PROJECTS))
    return projects


def may_query_global(user: User) -> bool:
    return has_permission(user.permissions, [Permissions.ANALYTICS_GLOBAL, Permissions.SYSTEM_MANAGE])


def team_scope_filter(user: User) -> dict[str, Any] | None:
    """Teams whose analytics the user may query, None for none; team:read_all alone opens no project data."""
    from app.api.v1.helpers.projects import may_read_projects
    from app.api.v1.helpers.teams import visible_teams_filter

    if may_query_global(user) or has_permission(user.permissions, Permissions.PROJECT_READ_ALL):
        return {}
    return visible_teams_filter(user) if may_read_projects(user) else None


@dataclass
class ResolvedScope:
    scope: ScopeKind
    scope_id: str | None
    project_ids: list[str] | None
    # The rows the resolver read for a user or team scope, handed to head resolution so it reads none.
    projects: list[ProjectWithScanId] | None = None


class ScopeResolver:
    def __init__(self, db: AsyncIOMotorDatabase, user: User) -> None:
        self.db = db
        self.user = user

    async def resolve(self, *, scope: ScopeKind, scope_id: str | None) -> ResolvedScope:
        if scope == "project":
            return await self._resolve_project(scope_id)
        if scope == "team":
            return await self._resolve_team(scope_id)
        if scope == "global":
            return self._resolve_global()
        if scope == "user":
            return await self._resolve_user()
        raise ScopeResolutionError(f"Unknown scope: {scope!r}")

    async def _resolve_project(self, scope_id: str | None) -> ResolvedScope:
        if not scope_id:
            raise ScopeResolutionError("project scope requires scope_id")
        if not await self._check_project_member(scope_id):
            raise ScopeResolutionError(f"User not authorised for project {scope_id}")
        return ResolvedScope(scope="project", scope_id=scope_id, project_ids=[scope_id])

    async def _resolve_team(self, scope_id: str | None) -> ResolvedScope:
        """The team's projects the user may read; global analytics reads them all, reading a team opens none."""
        from app.api.v1.helpers.projects import build_user_project_query

        if not scope_id:
            raise ScopeResolutionError("team scope requires scope_id")
        team_repo = TeamRepository(self.db)
        teams = team_scope_filter(self.user)
        if teams is None or not await team_repo.count(and_filters({"_id": scope_id}, teams)):
            raise ScopeResolutionError(f"User not authorised for team {scope_id}")
        readable = {} if may_query_global(self.user) else await build_user_project_query(self.user, team_repo)
        projects = await read_scope_projects(self.db, and_filters(readable, {"team_ids": scope_id}))
        return ResolvedScope(scope="team", scope_id=scope_id, project_ids=[p.id for p in projects], projects=projects)

    def _resolve_global(self) -> ResolvedScope:
        if not may_query_global(self.user):
            raise ScopeResolutionError("Global analytics requires analytics:global or system:manage")
        return ResolvedScope(scope="global", scope_id=None, project_ids=None)

    async def _resolve_user(self) -> ResolvedScope:
        projects = await self.list_user_projects()
        return ResolvedScope(scope="user", scope_id=None, project_ids=[p.id for p in projects], projects=projects)

    async def _check_project_member(self, project_id: str) -> bool:
        from app.api.v1.helpers.projects import check_project_access

        try:
            await check_project_access(project_id, self.user, self.db)
        except HTTPException:
            return False
        return True

    async def list_user_projects(self) -> list[ProjectWithScanId]:
        """Every project the user may see, under the query the project routes are filtered by."""
        from app.api.v1.helpers.projects import build_user_project_query

        return await read_scope_projects(self.db, await build_user_project_query(self.user, TeamRepository(self.db)))
