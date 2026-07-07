"""Shared helper functions for project-related operations."""

import secrets
from typing import Any, Dict, Optional, Tuple

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

_MSG_NOT_ENOUGH_PERMISSIONS = "Not enough permissions"


async def build_user_project_query(
    user: User,
    team_repo: TeamRepository,
) -> Dict[str, Any]:
    """Build a MongoDB query for projects the user can access (empty dict if read_all)."""
    if has_permission(user.permissions, Permissions.PROJECT_READ_ALL):
        return {}

    user_teams = await team_repo.find_by_member(str(user.id))
    team_ids = [t.id for t in user_teams]

    return {
        "$or": [
            {"members.user_id": str(user.id)},
            {"team_id": {"$in": team_ids}},
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


def _is_write_request(required_role: Optional[str]) -> bool:
    """Return True when ``required_role`` denotes a write (editor/admin) request."""
    return required_role in _WRITE_ROLES


def _max_role(role_a: Optional[str], role_b: Optional[str]) -> Optional[str]:
    """Return the higher of two project roles (by PROJECT_ROLES order); either may be None."""
    if role_a is None:
        return role_b
    if role_b is None:
        return role_a
    return role_a if PROJECT_ROLES.index(role_a) >= PROJECT_ROLES.index(role_b) else role_b


def _direct_member_role(project: Project, user_id: str) -> Optional[str]:
    """Return the user's direct project-member role, or ``None`` if not a member."""
    for member in project.members:
        if member.user_id == user_id:
            return member.role
    return None


async def _team_derived_role(
    project: Project,
    user_id: str,
    team_repo: TeamRepository,
) -> Optional[str]:
    """Return the project role from team membership: team admin -> admin, else viewer; None if not a team member."""
    if not project.team_id:
        return None
    team = await team_repo.get_raw_by_id(project.team_id)
    if not team:
        return None
    for tm in team.get("members", []):
        if tm.get("user_id") == user_id:
            return PROJECT_ROLE_ADMIN if tm.get("role") == TEAM_ROLE_ADMIN else PROJECT_ROLE_VIEWER
    return None


async def _resolve_effective_role(
    project: Project,
    user: User,
    team_repo: TeamRepository,
) -> tuple[bool, Optional[str]]:
    """Return (is_member, effective_role) where effective_role = MAX(direct, team-derived)."""
    user_id = str(user.id)
    direct_role = _direct_member_role(project, user_id)
    team_role = await _team_derived_role(project, user_id, team_repo)
    is_member = direct_role is not None or team_role is not None
    return is_member, _max_role(direct_role, team_role)


async def check_project_access(
    project_id: str,
    user: User,
    db: AsyncIOMotorDatabase,
    required_role: Optional[str] = None,
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

    if Permissions.PROJECT_READ not in user.permissions and Permissions.PROJECT_READ_ALL not in user.permissions:
        raise HTTPException(status_code=403, detail=_MSG_NOT_ENOUGH_PERMISSIONS)

    if required_role:
        current_role = effective_role or PROJECT_ROLE_VIEWER
        if PROJECT_ROLES.index(current_role) < PROJECT_ROLES.index(required_role):
            raise HTTPException(status_code=403, detail=_MSG_NOT_ENOUGH_PERMISSIONS)

    return project


def generate_project_api_key(project_id: str) -> Tuple[str, str]:
    """Generate a project API key, returning (api_key "project_id.secret", api_key_hash)."""
    secret = secrets.token_urlsafe(32)
    api_key = f"{project_id}.{secret}"
    api_key_hash = security.get_password_hash(secret)
    return api_key, api_key_hash


def apply_system_settings_enforcement(
    update_data: Dict[str, Any],
    retention_mode: str,
    rescan_mode: str,
) -> Dict[str, Any]:
    """Strip globally-enforced fields from project update data when their mode is "global"."""
    result = update_data.copy()

    if retention_mode == "global":
        result.pop("retention_days", None)
        result.pop("retention_action", None)

    if rescan_mode == "global":
        result.pop("rescan_enabled", None)
        result.pop("rescan_interval", None)

    return result
