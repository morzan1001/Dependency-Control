"""Shared helper functions for project-related operations."""

import secrets
from typing import Any

from fastapi import HTTPException
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.core import security
from app.core.constants import (
    PROJECT_ROLE_ADMIN,
    PROJECT_ROLE_EDITOR,
    PROJECT_ROLE_VIEWER,
    PROJECT_ROLES,
    SETTINGS_MODE_GLOBAL,
    TEAM_ROLE_ADMIN,
    ProjectRole,
)
from app.core.permissions import Permissions, has_permission
from app.models.project import Project
from app.models.user import User
from app.repositories.projects import ProjectRepository, surviving_admin_filter
from app.repositories.teams import TeamRepository
from app.services.analysis.registry import SELECTABLE_ANALYZERS

_MSG_NOT_ENOUGH_PERMISSIONS = "Not enough permissions"

# The filter for "no project at all". An empty dict already means the opposite here — the whole
# collection — so a refusal has to be spelled as a filter nothing matches.
NO_PROJECTS: dict[str, Any] = {"_id": {"$in": []}}


async def build_user_project_query(
    user: User,
    team_repo: TeamRepository,
) -> dict[str, Any]:
    """Build a MongoDB query for projects the user can access (empty dict if read_all).

    Membership and a project-read permission, the same two layers ``check_project_access``
    composes: a caller with neither permission reads no project through any surface, however many
    it is a member of.
    """
    if not may_read_projects(user):
        return NO_PROJECTS

    if has_permission(user.permissions, Permissions.PROJECT_READ_ALL):
        return {}

    return {
        "$or": [
            {"members.user_id": str(user.id)},
            # An element test, not a scalar equality: a project answers to every team that owns it,
            # so a co-owner's members see it whichever owner a writer left in the scalar.
            {"team_ids": {"$in": await team_repo.find_ids({"members.user_id": str(user.id)})}},
        ]
    }


_WRITE_ROLES = frozenset({PROJECT_ROLE_EDITOR, PROJECT_ROLE_ADMIN})


def is_write_superuser(user: User) -> bool:
    """True if the user may change any project; deleting one takes project:delete instead."""
    return has_permission(user.permissions, Permissions.PROJECT_UPDATE)


def may_read_projects(user: User) -> bool:
    """Whether the user holds a project-read permission at all.

    A project role says which projects, this says whether the user reads projects; every resource
    gate wants both, and one that settles for the role alone hands a member with no project
    permission the resource anyway.
    """
    return has_permission(user.permissions, [Permissions.PROJECT_READ, Permissions.PROJECT_READ_ALL])


def max_project_role(role_a: ProjectRole | None, role_b: ProjectRole | None) -> ProjectRole | None:
    """Return the higher of two project roles (by PROJECT_ROLES order); either may be None."""
    if role_a is None:
        return role_b
    if role_b is None:
        return role_a
    return role_a if PROJECT_ROLES.index(role_a) >= PROJECT_ROLES.index(role_b) else role_b


def team_grant_role(team_role: str | None) -> ProjectRole:
    """The project role membership of an owning team grants: team admin -> admin, member -> viewer."""
    return PROJECT_ROLE_ADMIN if team_role == TEAM_ROLE_ADMIN else PROJECT_ROLE_VIEWER


def direct_member_role(project: Project, user_id: str) -> ProjectRole | None:
    """Return the user's direct project-member role, or ``None`` if not a member."""
    return next((member.role for member in project.members if member.user_id == user_id), None)


async def team_derived_role(
    team_ids: list[str],
    user_id: str,
    team_repo: TeamRepository,
) -> ProjectRole | None:
    """The strongest project role any of these teams grants; array order only says which writer came last."""
    if not team_ids:
        return None
    role: ProjectRole | None = None
    for members in (await team_repo.members_by_team(team_ids)).values():
        for member in members:
            if member.get("user_id") == user_id:
                role = max_project_role(role, team_grant_role(member.get("role")))
    return role


async def effective_project_role(project: Project, user: User, team_repo: TeamRepository) -> ProjectRole | None:
    """MAX(direct, team-derived); None when the user is neither a member nor on an owning team."""
    user_id = str(user.id)
    return max_project_role(
        direct_member_role(project, user_id), await team_derived_role(project.team_ids, user_id, team_repo)
    )


async def admin_supplying_owners(team_ids: list[str], team_repo: TeamRepository) -> list[str]:
    """The teams among ``team_ids`` that have an admin, each of whom administers the project."""
    by_team = await team_repo.members_by_team(team_ids)
    return sorted(
        team_id
        for team_id, members in by_team.items()
        if any(member.get("role") == TEAM_ROLE_ADMIN for member in members)
    )


async def project_admin_ids(projects: list[Project], team_repo: TeamRepository) -> dict[str, set[str]]:
    """Each project's admins: its direct admin members and the admins of every team that owns it."""
    by_team = await team_repo.members_by_team(sorted({team_id for p in projects for team_id in p.team_ids}))
    team_admins = {
        team_id: {m["user_id"] for m in members if m.get("role") == TEAM_ROLE_ADMIN}
        for team_id, members in by_team.items()
    }
    return {
        p.id: {m.user_id for m in p.members if m.role == PROJECT_ROLE_ADMIN}.union(
            *(team_admins.get(team_id, set()) for team_id in p.team_ids)
        )
        for p in projects
    }


async def last_admin_guard(
    project: Project,
    user: User,
    team_repo: TeamRepository,
    *,
    surviving_owners: set[str] | None = None,
    leaving_member: str | None = None,
) -> dict[str, Any]:
    """The filter the write itself checks so the project keeps an admin despite concurrent writes; {} needs none."""
    if is_write_superuser(user):
        return {}
    if surviving_owners is not None:
        admin_owners = await admin_supplying_owners(sorted(surviving_owners), team_repo)
        if not set(admin_owners) <= set(project.team_ids):
            return {}
        return surviving_admin_filter(admin_owners)
    if leaving_member is not None and direct_member_role(project, leaving_member) == PROJECT_ROLE_ADMIN:
        return surviving_admin_filter(await admin_supplying_owners(project.team_ids, team_repo), leaving_member)
    return {}


async def check_project_access(
    project_id: str,
    user: User,
    db: AsyncIOMotorDatabase,
    required_role: ProjectRole | None = None,
    *,
    write: bool = False,
    global_permission: str = Permissions.PROJECT_UPDATE,
) -> Project:
    """Resolve project access and return the project, or raise 403/404.

    The single resource gate composing global permissions and project roles:
    None/viewer required_role is READ, editor/admin is WRITE; project:read_all is a
    READ-ONLY superuser (does not satisfy WRITE); ``global_permission`` (project:update,
    or project:delete for a deletion) bypasses membership; effective role = MAX(direct,
    team-derived); members must also hold project:read (or read_all). ``write`` makes the
    request WRITE without demanding a role, so membership in any role suffices.
    """
    project = await ProjectRepository(db).get_by_id(project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    if has_permission(user.permissions, global_permission):
        return project

    if not (write or required_role in _WRITE_ROLES) and has_permission(user.permissions, Permissions.PROJECT_READ_ALL):
        return project

    effective_role = await effective_project_role(project, user, TeamRepository(db))
    if effective_role is None or not may_read_projects(user):
        raise HTTPException(status_code=403, detail=_MSG_NOT_ENOUGH_PERMISSIONS)

    if required_role and PROJECT_ROLES.index(effective_role) < PROJECT_ROLES.index(required_role):
        raise HTTPException(status_code=403, detail=_MSG_NOT_ENOUGH_PERMISSIONS)

    return project


async def authorize_waiver_read(project_id: str | None, user: User, db: AsyncIOMotorDatabase) -> None:
    """waiver:read or read_all opens global waivers, read_all every project's, read the viewable projects'."""
    if not has_permission(user.permissions, [Permissions.WAIVER_READ, Permissions.WAIVER_READ_ALL]):
        raise HTTPException(status_code=403, detail=_MSG_NOT_ENOUGH_PERMISSIONS)
    if project_id and not has_permission(user.permissions, Permissions.WAIVER_READ_ALL):
        await check_project_access(project_id, user, db)


def generate_project_api_key(project_id: str) -> tuple[str, str]:
    """Generate a project API key, returning (api_key "project_id.secret", api_key_hash)."""
    secret = secrets.token_urlsafe(32)
    api_key = f"{project_id}.{secret}"
    api_key_hash = security.get_password_hash(secret)
    return api_key, api_key_hash


def apply_system_settings_enforcement(
    update_data: dict[str, Any],
    retention_mode: str,
    rescan_mode: str,
) -> dict[str, Any]:
    """Strip globally-enforced fields from project update data when their mode is "global"."""
    result = update_data.copy()

    if retention_mode == SETTINGS_MODE_GLOBAL:
        result.pop("retention_days", None)
        result.pop("retention_action", None)

    if rescan_mode == SETTINGS_MODE_GLOBAL:
        result.pop("rescan_enabled", None)
        result.pop("rescan_interval", None)

    return result


def reject_unknown_analyzers(names: list[str] | None) -> None:
    """The engine skips a name it does not know without a trace, so a typo would silently stop a scanner."""
    unknown = sorted(set(names or ()) - SELECTABLE_ANALYZERS)
    if unknown:
        raise HTTPException(status_code=422, detail=f"Unknown analyzers: {', '.join(unknown)}")
