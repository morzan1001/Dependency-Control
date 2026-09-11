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
    TEAM_ROLE_ADMIN,
)
from app.core.permissions import Permissions, has_permission
from app.models.project import Project
from app.models.user import User
from app.repositories import ProjectRepository, TeamRepository
from app.repositories.projects import surviving_owner_admin_filter

_MSG_NOT_ENOUGH_PERMISSIONS = "Not enough permissions"


async def build_user_project_query(
    user: User,
    team_repo: TeamRepository,
) -> dict[str, Any]:
    """Build a MongoDB query for projects the user can access (empty dict if read_all)."""
    if has_permission(user.permissions, Permissions.PROJECT_READ_ALL):
        return {}

    user_teams = await team_repo.find_by_member(str(user.id))
    team_ids = [t.id for t in user_teams]

    return {
        "$or": [
            {"members.user_id": str(user.id)},
            # An element test, not a scalar equality: a project answers to every team that owns it,
            # so a co-owner's members see it whichever owner a writer left in the scalar.
            {"team_ids": {"$in": team_ids}},
        ]
    }


# Roles that constitute a WRITE-level request; None/viewer are READ.
_WRITE_ROLES = frozenset({PROJECT_ROLE_EDITOR, PROJECT_ROLE_ADMIN})

# Global "manage any project" write-superuser permissions; project:delete is
# included so a delete-capable admin passes the delete gate without project:update.
_WRITE_SUPERUSER_PERMISSIONS = [Permissions.PROJECT_UPDATE, Permissions.PROJECT_DELETE]


def is_write_superuser(user: User) -> bool:
    """True if the user is a global write superuser (manage any project)."""
    return has_permission(user.permissions, _WRITE_SUPERUSER_PERMISSIONS)


def may_read_projects(user: User) -> bool:
    """Whether the user holds a project-read permission at all.

    A project role says which projects, this says whether the user reads projects; every resource
    gate wants both, and one that settles for the role alone hands a member with no project
    permission the resource anyway.
    """
    return has_permission(user.permissions, [Permissions.PROJECT_READ, Permissions.PROJECT_READ_ALL])


def _is_write_request(required_role: str | None) -> bool:
    """Return True when ``required_role`` denotes a write (editor/admin) request."""
    return required_role in _WRITE_ROLES


def max_project_role(role_a: str | None, role_b: str | None) -> str | None:
    """Return the higher of two project roles (by PROJECT_ROLES order); either may be None."""
    if role_a is None:
        return role_b
    if role_b is None:
        return role_a
    return role_a if PROJECT_ROLES.index(role_a) >= PROJECT_ROLES.index(role_b) else role_b


def _direct_member_role(project: Project, user_id: str) -> str | None:
    """Return the user's direct project-member role, or ``None`` if not a member."""
    for member in project.members:
        if member.user_id == user_id:
            return member.role
    return None


async def team_derived_role(
    team_ids: list[str],
    user_id: str,
    team_repo: TeamRepository,
) -> str | None:
    """The strongest project role any of these teams grants: team admin -> admin, member -> viewer.

    Strongest rather than first, because array order is set by whichever writer touched the field
    last and must not decide who may write.
    """
    role: str | None = None
    for team_id in team_ids:
        team = await team_repo.get_raw_by_id(team_id)
        if not team:
            continue
        for member in team.get("members", []):
            if member.get("user_id") == user_id:
                granted = PROJECT_ROLE_ADMIN if member.get("role") == TEAM_ROLE_ADMIN else PROJECT_ROLE_VIEWER
                role = max_project_role(role, granted)
    return role


async def admin_survival_guard(
    project: Project,
    surviving_owners: set[str],
    team_repo: TeamRepository,
) -> dict[str, Any]:
    """The write filter under which an ownership change keeps someone able to administer the project.

    A filter rather than a verdict: which teams supply an admin is answered from the ``teams``
    collection and cannot be part of a query on ``projects``, but *which of them the project still
    holds* can, and that is the half a concurrent write invalidates. An empty filter is a write
    that brings its own admin along; one naming no owner matches nothing, which is the refusal.
    """
    incumbent: list[str] = []
    for owner_id in sorted(surviving_owners):
        team = await team_repo.get_raw_by_id(owner_id)
        if not team or not any(member.get("role") == TEAM_ROLE_ADMIN for member in team.get("members", [])):
            continue
        if owner_id not in project.team_ids:
            return {}
        incumbent.append(owner_id)
    return surviving_owner_admin_filter(incumbent)


async def _resolve_effective_role(
    project: Project,
    user: User,
    team_repo: TeamRepository,
) -> tuple[bool, str | None]:
    """Return (is_member, effective_role) where effective_role = MAX(direct, team-derived)."""
    user_id = str(user.id)
    direct_role = _direct_member_role(project, user_id)
    team_role = await team_derived_role(project.team_ids, user_id, team_repo)
    is_member = direct_role is not None or team_role is not None
    return is_member, max_project_role(direct_role, team_role)


async def check_project_access(
    project_id: str,
    user: User,
    db: AsyncIOMotorDatabase,
    required_role: str | None = None,
) -> Project:
    """Resolve project access and return the project, or raise 403/404.

    The single resource gate composing global permissions and project roles:
    None/viewer required_role is READ, editor/admin is WRITE; project:read_all is a
    READ-ONLY superuser (does not satisfy WRITE); project:update/project:delete is the
    WRITE superuser bypassing membership; effective role = MAX(direct, team-derived);
    members must also hold project:read (or read_all).
    """
    project_repo = ProjectRepository(db)
    team_repo = TeamRepository(db)

    project = await project_repo.get_by_id(project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    write_request = _is_write_request(required_role)

    if is_write_superuser(user):
        return project

    if not write_request and has_permission(user.permissions, Permissions.PROJECT_READ_ALL):
        return project

    is_member, effective_role = await _resolve_effective_role(project, user, team_repo)

    if not is_member:
        raise HTTPException(status_code=403, detail=_MSG_NOT_ENOUGH_PERMISSIONS)

    if not may_read_projects(user):
        raise HTTPException(status_code=403, detail=_MSG_NOT_ENOUGH_PERMISSIONS)

    if required_role:
        current_role = effective_role or PROJECT_ROLE_VIEWER
        if PROJECT_ROLES.index(current_role) < PROJECT_ROLES.index(required_role):
            raise HTTPException(status_code=403, detail=_MSG_NOT_ENOUGH_PERMISSIONS)

    return project


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

    if retention_mode == "global":
        result.pop("retention_days", None)
        result.pop("retention_action", None)

    if rescan_mode == "global":
        result.pop("rescan_enabled", None)
        result.pop("rescan_interval", None)

    return result
