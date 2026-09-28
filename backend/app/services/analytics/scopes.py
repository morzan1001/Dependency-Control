"""Scope resolution for analytics queries.

Translates a (scope, scope_id) pair into a ResolvedScope carrying the project_ids the caller is
authorised to query. Permission gating is enforced here so query functions stay scope-agnostic.
"""

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Literal, TypeVar

from fastapi import HTTPException
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.core.constants import ANALYTICS_MAX_QUERY_LIMIT
from app.core.permissions import Permissions, has_permission
from app.repositories.base import and_filters
from app.repositories.projects import ProjectRepository
from app.repositories.teams import TeamRepository

_SCOPE_TOO_LARGE = (
    "This scope holds more than {limit} projects. Analytics is answered over a materialised "
    "project list and nothing in the response can name the projects a longer one would drop, "
    "so the request is refused rather than answered over an arbitrary subset. Query a team or "
    "a single project."
)

_T = TypeVar("_T")

if TYPE_CHECKING:
    from app.models.user import User
    from app.schemas.projections import ProjectWithScanId

Scope = Literal["project", "team", "global", "user"]


class ScopeResolutionError(PermissionError):
    """Raised when the caller is not allowed to query the requested scope."""


class ScopeTooLargeError(Exception):
    """Raised when a scope holds more projects than analytics can materialise as one id list."""


def scope_probe_limit() -> int:
    """One past the ceiling, so a scope sitting exactly on it is answered instead of refused."""
    return ANALYTICS_MAX_QUERY_LIMIT + 1


def ensure_whole_scope(rows: list[_T]) -> list[_T]:
    """``rows``, or a refusal when the read that produced them came back over the ceiling.

    Measured at 120 000 projects against MongoDB 7: the id list costs 60 ms and ~40 MiB, and the
    ``$in`` it becomes downstream encodes to 4.8 MiB against the 16 MB BSON command limit, so the
    ceiling sits roughly a factor of four below where the query would fail on its own.
    """
    if len(rows) > ANALYTICS_MAX_QUERY_LIMIT:
        raise ScopeTooLargeError(_SCOPE_TOO_LARGE.format(limit=ANALYTICS_MAX_QUERY_LIMIT))
    return rows


def may_query_global(user: "User") -> bool:
    return has_permission(user.permissions, [Permissions.ANALYTICS_GLOBAL, Permissions.SYSTEM_MANAGE])


def team_scope_filter(user: "User") -> dict[str, Any] | None:
    """Teams whose analytics the user may query, None for none; team:read_all alone opens no project data."""
    from app.api.v1.helpers.projects import may_read_projects
    from app.api.v1.helpers.teams import visible_teams_filter

    if may_query_global(user) or has_permission(user.permissions, Permissions.PROJECT_READ_ALL):
        return {}
    return visible_teams_filter(user) if may_read_projects(user) else None


@dataclass
class ResolvedScope:
    scope: Scope
    scope_id: str | None
    project_ids: list[str] | None


class ScopeResolver:
    def __init__(self, db: AsyncIOMotorDatabase, user: "User | Any") -> None:
        self.db = db
        self.user = user

    async def resolve(self, *, scope: Scope, scope_id: str | None) -> ResolvedScope:
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
        projects = await ProjectRepository(self.db).find_many_minimal(
            and_filters(readable, {"team_ids": scope_id}), limit=scope_probe_limit()
        )
        return ResolvedScope(
            scope="team", scope_id=scope_id, project_ids=[str(p.id) for p in ensure_whole_scope(projects)]
        )

    def _resolve_global(self) -> ResolvedScope:
        if not may_query_global(self.user):
            raise ScopeResolutionError("Global analytics requires analytics:global or system:manage")
        return ResolvedScope(scope="global", scope_id=None, project_ids=None)

    async def _resolve_user(self) -> ResolvedScope:
        project_ids = [str(p.id) for p in await self.list_user_projects()]
        return ResolvedScope(scope="user", scope_id=None, project_ids=project_ids)

    async def _check_project_member(self, project_id: str) -> bool:
        from app.api.v1.helpers.projects import check_project_access

        try:
            await check_project_access(project_id, self.user, self.db)
        except HTTPException:
            return False
        return True

    async def list_user_projects(self) -> list["ProjectWithScanId"]:
        """Every project the user may see, under the same query the project routes are filtered by,
        with the fields scan resolution and a name map need, so no caller reads them again.

        Shared rather than restated: two spellings of one access rule drift, and the half that
        drifts is invisible until someone is shown a project the other spelling would have hidden.
        A read-all user gets an empty filter, which is the whole collection.
        """
        from app.api.v1.helpers.projects import build_user_project_query

        query = await build_user_project_query(self.user, TeamRepository(self.db))
        projects = await ProjectRepository(self.db).find_many_with_scan_id(query, limit=scope_probe_limit())
        return ensure_whole_scope(projects)
