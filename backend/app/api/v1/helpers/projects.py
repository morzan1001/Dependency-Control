"""
Project Helper Functions

Shared helper functions for project-related operations.
"""

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
    """
    Build a MongoDB query to filter projects the user has access to.

    This includes projects where:
    - User is a direct member of the project
    - User is a member of the project's team

    Args:
        user: The current user
        team_repo: TeamRepository instance for team lookups

    Returns:
        MongoDB query dict. Empty dict if user has read_all permission.
    """
    if has_permission(user.permissions, Permissions.PROJECT_READ_ALL):
        return {}

    # Find teams user is member of
    user_teams = await team_repo.find_by_member(str(user.id))
    team_ids = [t.id for t in user_teams]

    return {
        "$or": [
            {"members.user_id": str(user.id)},
            {"team_id": {"$in": team_ids}},
        ]
    }


# Roles that constitute a WRITE-level request. ``None``/``viewer`` are READ.
_WRITE_ROLES = frozenset({PROJECT_ROLE_EDITOR, PROJECT_ROLE_ADMIN})

# Global permissions that act as a WRITE ("manage any project") superuser.
# project:delete is included so a delete-capable global admin satisfies the
# admin-level gate guarding delete paths even without project:update.
_WRITE_SUPERUSER_PERMISSIONS = [Permissions.PROJECT_UPDATE, Permissions.PROJECT_DELETE]


def is_write_superuser(user: User) -> bool:
    """True if the user is a global write superuser (manage any project)."""
    return has_permission(user.permissions, _WRITE_SUPERUSER_PERMISSIONS)


def _is_write_request(required_role: Optional[str]) -> bool:
    """Return True when ``required_role`` denotes a write (editor/admin) request."""
    return required_role in _WRITE_ROLES


def _max_role(role_a: Optional[str], role_b: Optional[str]) -> Optional[str]:
    """Return the higher of two project roles by ``PROJECT_ROLES`` order.

    Either argument may be ``None`` (absent). Never downgrades a present role.
    """
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
    """Return the project role derived from team membership, or ``None``.

    Team admins map to project admin; other team members map to project viewer.
    """
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
    """Compute membership and the effective project role for ``user``.

    Effective role = MAX(direct member role, team-derived role) so a higher
    direct role is never downgraded by team membership (and vice versa).

    Returns ``(is_member, effective_role)``.
    """
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

    This is the single resource gate for project authorization. It composes two
    layers — global string permissions and project roles — into one rule:

    * ``required_role`` of ``None`` or ``"viewer"`` is a READ request;
      ``"editor"``/``"admin"`` is a WRITE request.
    * **project:read_all** is a READ-ONLY superuser: it grants READ access to
      any project but does NOT satisfy a WRITE ``required_role``. A read_all
      holder requesting write falls through to the write-superuser / membership
      checks.
    * **project:update** (and **project:delete**) is the WRITE superuser
      ("manage any project"), applied UNIFORMLY across every write path. A
      holder bypasses membership for write requests. project:update is
      admin-preset-only.
    * **Effective project role = MAX(direct member role, team-derived role)** —
      a higher direct role is never downgraded by team membership. Team admins
      map to project admin; other team members map to project viewer.
    * **Read feature-gate:** a project member must additionally hold
      ``project:read`` (or ``project:read_all``); otherwise access is denied.

    Args:
        project_id: The project ID to check access for.
        user: The current user.
        db: Database instance.
        required_role: Optional minimum project role required.

    Returns:
        The Project object if access is granted.

    Raises:
        HTTPException: 404 if project not found, 403 if access denied.
    """
    project_repo = ProjectRepository(db)
    team_repo = TeamRepository(db)

    project = await project_repo.get_by_id(project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    write_request = _is_write_request(required_role)

    # WRITE superuser ("manage any project"): project:update / project:delete
    # bypass membership for ANY request (write implies read), applied uniformly
    # across all write paths.
    if is_write_superuser(user):
        return project

    # READ-ONLY superuser: read_all grants READ access only. It must NOT satisfy
    # a write request — fall through to membership for those.
    if not write_request and has_permission(user.permissions, Permissions.PROJECT_READ_ALL):
        return project

    is_member, effective_role = await _resolve_effective_role(project, user, team_repo)

    if not is_member:
        raise HTTPException(status_code=403, detail=_MSG_NOT_ENOUGH_PERMISSIONS)

    # Read feature-gate: members still need project:read (or read_all).
    if Permissions.PROJECT_READ not in user.permissions and Permissions.PROJECT_READ_ALL not in user.permissions:
        raise HTTPException(status_code=403, detail=_MSG_NOT_ENOUGH_PERMISSIONS)

    if required_role:
        current_role = effective_role or PROJECT_ROLE_VIEWER
        if PROJECT_ROLES.index(current_role) < PROJECT_ROLES.index(required_role):
            raise HTTPException(status_code=403, detail=_MSG_NOT_ENOUGH_PERMISSIONS)

    return project


def generate_project_api_key(project_id: str) -> Tuple[str, str]:
    """
    Generate a new API key for a project.

    Args:
        project_id: The project ID to generate a key for

    Returns:
        Tuple of (api_key, api_key_hash)
        - api_key: The full API key in format "project_id.secret"
        - api_key_hash: The hashed secret for storage
    """
    secret = secrets.token_urlsafe(32)
    api_key = f"{project_id}.{secret}"
    api_key_hash = security.get_password_hash(secret)
    return api_key, api_key_hash


def apply_system_settings_enforcement(
    update_data: Dict[str, Any],
    retention_mode: str,
    rescan_mode: str,
) -> Dict[str, Any]:
    """
    Apply system settings enforcement to project update data.

    Removes fields that are globally enforced and cannot be changed per-project.

    Args:
        update_data: Dictionary of fields to update
        retention_mode: "global" or "per_project"
        rescan_mode: "global" or "per_project"

    Returns:
        Updated data dictionary with enforced fields removed
    """
    result = update_data.copy()

    if retention_mode == "global":
        result.pop("retention_days", None)
        result.pop("retention_action", None)

    if rescan_mode == "global":
        result.pop("rescan_enabled", None)
        result.pop("rescan_interval", None)

    return result
