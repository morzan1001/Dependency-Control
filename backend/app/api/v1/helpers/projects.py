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
    PROJECT_ROLE_VIEWER,
    PROJECT_ROLES,
    TEAM_ROLE_ADMIN,
    TEAM_ROLE_OWNER,
)
from app.core.permissions import has_permission
from app.models.project import Project
from app.models.user import User
from app.repositories import ProjectRepository, TeamRepository


async def build_user_project_query(
    user: User,
    team_repo: TeamRepository,
) -> Dict[str, Any]:
    """
    Build a MongoDB query to filter projects the user has access to.

    This includes projects where:
    - User is the owner
    - User is a direct member
    - User is a member of the project's team

    Args:
        user: The current user
        team_repo: TeamRepository instance for team lookups

    Returns:
        MongoDB query dict. Empty dict if user has read_all permission.
    """
    if has_permission(user.permissions, "project:read_all"):
        return {}

    # Find teams user is member of
    user_teams = await team_repo.find_by_member(str(user.id))
    team_ids = [t.id for t in user_teams]

    return {
        "$or": [
            {"owner_id": str(user.id)},
            {"members.user_id": str(user.id)},
            {"team_id": {"$in": team_ids}},
        ]
    }


async def check_project_access(
    project_id: str,
    user: User,
    db: AsyncIOMotorDatabase,
    required_role: Optional[str] = None,
) -> Project:
    """
    Check if a user has access to a project and return the project.

    Args:
        project_id: The project ID to check access for
        user: The current user
        db: Database instance
        required_role: Optional minimum role required (viewer, editor, admin)

    Returns:
        The Project object if access is granted

    Raises:
        HTTPException: 404 if project not found, 403 if access denied
    """
    project_repo = ProjectRepository(db)
    team_repo = TeamRepository(db)

    project = await project_repo.get_by_id(project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    # SECURITY: project:read_all grants access to ALL projects (superuser)
    # Note: project:update does NOT bypass membership checks - only grants write permission
    if has_permission(user.permissions, "project:read_all"):
        return project

    is_owner = project.owner_id == str(user.id)
    is_member = False
    member_role = None

    for member in project.members:
        if member.user_id == str(user.id):
            is_member = True
            member_role = member.role
            break

    # Check team membership if project belongs to a team
    if project.team_id:
        team = await team_repo.get_raw_by_id(project.team_id)
        if team:
            for tm in team.get("members", []):
                if tm["user_id"] == str(user.id):
                    # Team members get 'viewer' access by default,
                    # Team admins/owners get 'admin' access on project.
                    if tm["role"] in [TEAM_ROLE_ADMIN, TEAM_ROLE_OWNER]:
                        member_role = PROJECT_ROLE_ADMIN
                    else:
                        member_role = PROJECT_ROLE_VIEWER
                    is_member = True
                    break

    if not (is_owner or is_member):
        raise HTTPException(status_code=403, detail="Not enough permissions")

    # Check for basic read permission
    if "project:read" not in user.permissions and "project:read_all" not in user.permissions:
        raise HTTPException(status_code=403, detail="Not enough permissions")

    if required_role:
        if is_owner:
            return project
        # Role hierarchy: admin > editor > viewer
        roles = PROJECT_ROLES
        # If member_role is None, default to viewer
        current_role = member_role or PROJECT_ROLE_VIEWER
        if roles.index(current_role) < roles.index(required_role):
            raise HTTPException(status_code=403, detail="Not enough permissions")

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

    if rescan_mode == "global":
        result.pop("rescan_enabled", None)
        result.pop("rescan_interval", None)

    return result
