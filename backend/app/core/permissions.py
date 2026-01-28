"""
Permission System Constants and Helpers

This module provides a centralized, fine-grained permission system.
No wildcard ("*") permissions are used - admins have all individual permissions explicitly.
"""

from typing import List, Union


class Permissions:
    """All available permissions in the system."""

    # ==========================================================================
    # System Management
    # ==========================================================================
    SYSTEM_MANAGE = "system:manage"

    # ==========================================================================
    # User Management
    # ==========================================================================
    USER_CREATE = "user:create"
    USER_READ = "user:read"
    USER_READ_ALL = "user:read_all"
    USER_UPDATE = "user:update"
    USER_DELETE = "user:delete"
    USER_MANAGE = "user:manage"  # Legacy: combines create/read_all/update/delete

    # ==========================================================================
    # Team Management
    # ==========================================================================
    TEAM_CREATE = "team:create"
    TEAM_READ = "team:read"
    TEAM_READ_ALL = "team:read_all"
    TEAM_UPDATE = "team:update"
    TEAM_DELETE = "team:delete"

    # ==========================================================================
    # Project Management
    # ==========================================================================
    PROJECT_CREATE = "project:create"
    PROJECT_READ = "project:read"
    PROJECT_READ_ALL = "project:read_all"
    PROJECT_UPDATE = "project:update"
    PROJECT_DELETE = "project:delete"

    # ==========================================================================
    # Analytics
    # ==========================================================================
    ANALYTICS_READ = "analytics:read"
    ANALYTICS_SUMMARY = "analytics:summary"
    ANALYTICS_DEPENDENCIES = "analytics:dependencies"
    ANALYTICS_TREE = "analytics:tree"
    ANALYTICS_IMPACT = "analytics:impact"
    ANALYTICS_HOTSPOTS = "analytics:hotspots"
    ANALYTICS_SEARCH = "analytics:search"
    ANALYTICS_RECOMMENDATIONS = "analytics:recommendations"

    # ==========================================================================
    # Notifications
    # ==========================================================================
    NOTIFICATIONS_BROADCAST = "notifications:broadcast"

    # ==========================================================================
    # Waivers
    # ==========================================================================
    WAIVER_READ = "waiver:read"
    WAIVER_READ_ALL = "waiver:read_all"
    WAIVER_MANAGE = "waiver:manage"
    WAIVER_DELETE = "waiver:delete"

    # ==========================================================================
    # Webhooks
    # ==========================================================================
    WEBHOOK_CREATE = "webhook:create"
    WEBHOOK_READ = "webhook:read"
    WEBHOOK_UPDATE = "webhook:update"
    WEBHOOK_DELETE = "webhook:delete"


# All permissions in the system (excluding internal/special permissions like auth:setup_2fa)
ALL_PERMISSIONS: List[str] = [
    # System
    Permissions.SYSTEM_MANAGE,
    # User
    Permissions.USER_CREATE,
    Permissions.USER_READ,
    Permissions.USER_READ_ALL,
    Permissions.USER_UPDATE,
    Permissions.USER_DELETE,
    Permissions.USER_MANAGE,
    # Team
    Permissions.TEAM_CREATE,
    Permissions.TEAM_READ,
    Permissions.TEAM_READ_ALL,
    Permissions.TEAM_UPDATE,
    Permissions.TEAM_DELETE,
    # Project
    Permissions.PROJECT_CREATE,
    Permissions.PROJECT_READ,
    Permissions.PROJECT_READ_ALL,
    Permissions.PROJECT_UPDATE,
    Permissions.PROJECT_DELETE,
    # Analytics
    Permissions.ANALYTICS_READ,
    Permissions.ANALYTICS_SUMMARY,
    Permissions.ANALYTICS_DEPENDENCIES,
    Permissions.ANALYTICS_TREE,
    Permissions.ANALYTICS_IMPACT,
    Permissions.ANALYTICS_HOTSPOTS,
    Permissions.ANALYTICS_SEARCH,
    Permissions.ANALYTICS_RECOMMENDATIONS,
    # Notifications
    Permissions.NOTIFICATIONS_BROADCAST,
    # Waivers
    Permissions.WAIVER_READ,
    Permissions.WAIVER_READ_ALL,
    Permissions.WAIVER_MANAGE,
    Permissions.WAIVER_DELETE,
    # Webhooks
    Permissions.WEBHOOK_CREATE,
    Permissions.WEBHOOK_READ,
    Permissions.WEBHOOK_UPDATE,
    Permissions.WEBHOOK_DELETE,
]


# =============================================================================
# Permission Presets
# =============================================================================

# Admin: All permissions
PRESET_ADMIN: List[str] = ALL_PERMISSIONS.copy()

# Regular User: Can create/manage own projects and teams, view analytics
PRESET_USER: List[str] = [
    # User - can view own profile
    Permissions.USER_READ,
    # Team - can create and view teams
    Permissions.TEAM_CREATE,
    Permissions.TEAM_READ,
    # Project - can create and view projects
    Permissions.PROJECT_CREATE,
    Permissions.PROJECT_READ,
    # Analytics - can view all analytics for accessible projects
    Permissions.ANALYTICS_READ,
    Permissions.ANALYTICS_SUMMARY,
    Permissions.ANALYTICS_DEPENDENCIES,
    Permissions.ANALYTICS_TREE,
    Permissions.ANALYTICS_IMPACT,
    Permissions.ANALYTICS_HOTSPOTS,
    Permissions.ANALYTICS_SEARCH,
    Permissions.ANALYTICS_RECOMMENDATIONS,
    # Waivers - can view own waivers
    Permissions.WAIVER_READ,
]

# Viewer: Read-only access
PRESET_VIEWER: List[str] = [
    # User - can view own profile
    Permissions.USER_READ,
    # Team - can view teams they belong to
    Permissions.TEAM_READ,
    # Project - can view projects they have access to
    Permissions.PROJECT_READ,
    # Analytics - can view summaries
    Permissions.ANALYTICS_READ,
    Permissions.ANALYTICS_SUMMARY,
    # Waivers - can view waivers
    Permissions.WAIVER_READ,
]


# =============================================================================
# Permission Groups for UI
# =============================================================================

PERMISSION_GROUPS = [
    {
        "id": "system",
        "name": "System",
        "description": "System-wide administrative permissions",
        "permissions": [
            {
                "id": Permissions.SYSTEM_MANAGE,
                "name": "System Management",
                "description": "Manage system settings and configuration",
            },
        ],
    },
    {
        "id": "user",
        "name": "User Management",
        "description": "Permissions for managing users",
        "permissions": [
            {
                "id": Permissions.USER_CREATE,
                "name": "Create Users",
                "description": "Create new user accounts",
            },
            {
                "id": Permissions.USER_READ,
                "name": "Read Users",
                "description": "View own user profile",
            },
            {
                "id": Permissions.USER_READ_ALL,
                "name": "Read All Users",
                "description": "View all user accounts",
            },
            {
                "id": Permissions.USER_UPDATE,
                "name": "Update Users",
                "description": "Modify user accounts",
            },
            {
                "id": Permissions.USER_DELETE,
                "name": "Delete Users",
                "description": "Delete user accounts",
            },
            {
                "id": Permissions.USER_MANAGE,
                "name": "Manage Users",
                "description": "Full user management access (legacy)",
            },
        ],
    },
    {
        "id": "team",
        "name": "Team Management",
        "description": "Permissions for managing teams",
        "permissions": [
            {
                "id": Permissions.TEAM_CREATE,
                "name": "Create Teams",
                "description": "Create new teams",
            },
            {
                "id": Permissions.TEAM_READ,
                "name": "Read Teams",
                "description": "View teams you belong to",
            },
            {
                "id": Permissions.TEAM_READ_ALL,
                "name": "Read All Teams",
                "description": "View all teams in the system",
            },
            {
                "id": Permissions.TEAM_UPDATE,
                "name": "Update Teams",
                "description": "Modify any team",
            },
            {
                "id": Permissions.TEAM_DELETE,
                "name": "Delete Teams",
                "description": "Delete any team",
            },
        ],
    },
    {
        "id": "project",
        "name": "Project Management",
        "description": "Permissions for managing projects",
        "permissions": [
            {
                "id": Permissions.PROJECT_CREATE,
                "name": "Create Projects",
                "description": "Create new projects",
            },
            {
                "id": Permissions.PROJECT_READ,
                "name": "Read Projects",
                "description": "View projects you have access to",
            },
            {
                "id": Permissions.PROJECT_READ_ALL,
                "name": "Read All Projects",
                "description": "View all projects in the system",
            },
            {
                "id": Permissions.PROJECT_UPDATE,
                "name": "Update Projects",
                "description": "Modify any project",
            },
            {
                "id": Permissions.PROJECT_DELETE,
                "name": "Delete Projects",
                "description": "Delete any project",
            },
        ],
    },
    {
        "id": "analytics",
        "name": "Analytics",
        "description": "Permissions for viewing analytics",
        "permissions": [
            {
                "id": Permissions.ANALYTICS_READ,
                "name": "Read Analytics",
                "description": "Basic analytics access",
            },
            {
                "id": Permissions.ANALYTICS_SUMMARY,
                "name": "View Summary",
                "description": "View analytics summaries",
            },
            {
                "id": Permissions.ANALYTICS_DEPENDENCIES,
                "name": "View Dependencies",
                "description": "View dependency analytics",
            },
            {
                "id": Permissions.ANALYTICS_TREE,
                "name": "View Dependency Tree",
                "description": "View dependency tree visualization",
            },
            {
                "id": Permissions.ANALYTICS_IMPACT,
                "name": "View Impact Analysis",
                "description": "View vulnerability impact analysis",
            },
            {
                "id": Permissions.ANALYTICS_HOTSPOTS,
                "name": "View Hotspots",
                "description": "View security hotspots",
            },
            {
                "id": Permissions.ANALYTICS_SEARCH,
                "name": "Search Analytics",
                "description": "Search across analytics data",
            },
            {
                "id": Permissions.ANALYTICS_RECOMMENDATIONS,
                "name": "View Recommendations",
                "description": "View security recommendations",
            },
        ],
    },
    {
        "id": "notifications",
        "name": "Notifications",
        "description": "Permissions for notifications",
        "permissions": [
            {
                "id": Permissions.NOTIFICATIONS_BROADCAST,
                "name": "Broadcast Notifications",
                "description": "Send notifications to all users",
            },
        ],
    },
    {
        "id": "waiver",
        "name": "Waivers",
        "description": "Permissions for managing waivers",
        "permissions": [
            {
                "id": Permissions.WAIVER_READ,
                "name": "Read Waivers",
                "description": "View own waivers",
            },
            {
                "id": Permissions.WAIVER_READ_ALL,
                "name": "Read All Waivers",
                "description": "View all waivers in the system",
            },
            {
                "id": Permissions.WAIVER_MANAGE,
                "name": "Manage Waivers",
                "description": "Create and modify waivers",
            },
            {
                "id": Permissions.WAIVER_DELETE,
                "name": "Delete Waivers",
                "description": "Delete any waiver",
            },
        ],
    },
    {
        "id": "webhook",
        "name": "Webhooks",
        "description": "Permissions for managing webhooks",
        "permissions": [
            {
                "id": Permissions.WEBHOOK_CREATE,
                "name": "Create Webhooks",
                "description": "Create new webhooks",
            },
            {
                "id": Permissions.WEBHOOK_READ,
                "name": "Read Webhooks",
                "description": "View webhook configurations",
            },
            {
                "id": Permissions.WEBHOOK_UPDATE,
                "name": "Update Webhooks",
                "description": "Modify existing webhooks",
            },
            {
                "id": Permissions.WEBHOOK_DELETE,
                "name": "Delete Webhooks",
                "description": "Delete webhooks",
            },
        ],
    },
]


# =============================================================================
# Helper Functions
# =============================================================================


def has_permission(
    user_permissions: List[str],
    required: Union[str, List[str]],
    require_all: bool = False,
) -> bool:
    """
    Check if user has the required permission(s).

    Args:
        user_permissions: List of permissions the user has
        required: Single permission or list of permissions to check
        require_all: If True, user must have ALL required permissions.
                    If False (default), user must have ANY of the required permissions.

    Returns:
        True if permission check passes, False otherwise.
    """
    if isinstance(required, str):
        required = [required]

    if require_all:
        # User must have ALL required permissions
        return all(perm in user_permissions for perm in required)
    else:
        # User must have ANY of the required permissions
        return any(perm in user_permissions for perm in required)


def get_missing_permissions(
    user_permissions: List[str],
    required: Union[str, List[str]],
) -> List[str]:
    """
    Get list of permissions the user is missing.

    Args:
        user_permissions: List of permissions the user has
        required: Single permission or list of permissions to check

    Returns:
        List of permissions the user doesn't have.
    """
    if isinstance(required, str):
        required = [required]

    return [perm for perm in required if perm not in user_permissions]
