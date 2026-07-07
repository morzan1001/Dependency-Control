"""Centralized fine-grained permission constants and helpers (no wildcard permissions).

Project access composes two layers — global permissions (this module) and ordered project
roles (viewer < editor < admin) — enforced by ``check_project_access`` in
``app/api/v1/helpers/projects.py``. Canonical model: ``docs/superpowers/specs/authz-model.md``.
"""

from typing import List


class Permissions:
    """All available permissions in the system."""

    SYSTEM_MANAGE = "system:manage"

    USER_CREATE = "user:create"
    USER_READ = "user:read"
    USER_READ_ALL = "user:read_all"
    USER_UPDATE = "user:update"
    USER_DELETE = "user:delete"
    USER_MANAGE_PERMISSIONS = "user:manage_permissions"

    TEAM_CREATE = "team:create"
    TEAM_READ = "team:read"
    TEAM_READ_ALL = "team:read_all"
    TEAM_UPDATE = "team:update"
    TEAM_DELETE = "team:delete"

    PROJECT_CREATE = "project:create"
    PROJECT_READ = "project:read"
    PROJECT_READ_ALL = "project:read_all"
    PROJECT_UPDATE = "project:update"
    PROJECT_DELETE = "project:delete"

    ANALYTICS_READ = "analytics:read"
    ANALYTICS_SUMMARY = "analytics:summary"
    ANALYTICS_DEPENDENCIES = "analytics:dependencies"
    ANALYTICS_TREE = "analytics:tree"
    ANALYTICS_IMPACT = "analytics:impact"
    ANALYTICS_HOTSPOTS = "analytics:hotspots"
    ANALYTICS_SEARCH = "analytics:search"
    ANALYTICS_RECOMMENDATIONS = "analytics:recommendations"
    ANALYTICS_GLOBAL = "analytics:global"

    NOTIFICATIONS_BROADCAST = "notifications:broadcast"

    WAIVER_READ = "waiver:read"
    WAIVER_READ_ALL = "waiver:read_all"
    WAIVER_MANAGE = "waiver:manage"
    WAIVER_DELETE = "waiver:delete"

    WEBHOOK_CREATE = "webhook:create"
    WEBHOOK_READ = "webhook:read"
    WEBHOOK_UPDATE = "webhook:update"
    WEBHOOK_DELETE = "webhook:delete"

    ARCHIVE_READ = "archive:read"
    ARCHIVE_RESTORE = "archive:restore"
    ARCHIVE_DOWNLOAD = "archive:download"
    ARCHIVE_READ_ALL = "archive:read_all"

    # Chat
    CHAT_ACCESS = "chat:access"
    CHAT_HISTORY_READ = "chat:history_read"
    CHAT_HISTORY_DELETE = "chat:history_delete"

    # MCP (external LLM clients calling our tools via API key)
    MCP_ACCESS = "mcp:access"


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
    Permissions.USER_MANAGE_PERMISSIONS,
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
    Permissions.ANALYTICS_GLOBAL,
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
    # Archives
    Permissions.ARCHIVE_READ,
    Permissions.ARCHIVE_RESTORE,
    Permissions.ARCHIVE_DOWNLOAD,
    Permissions.ARCHIVE_READ_ALL,
    # Chat
    Permissions.CHAT_ACCESS,
    Permissions.CHAT_HISTORY_READ,
    Permissions.CHAT_HISTORY_DELETE,
    # MCP
    Permissions.MCP_ACCESS,
]

def has_permission(
    user_permissions: List[str],
    required: str | List[str],
    require_all: bool = False,
) -> bool:
    """Check whether the user has ALL (require_all) or ANY (default) of the required permissions."""
    if isinstance(required, str):
        required = [required]

    if require_all:
        return all(perm in user_permissions for perm in required)
    return any(perm in user_permissions for perm in required)


def get_missing_permissions(
    user_permissions: List[str],
    required: str | List[str],
) -> List[str]:
    """Return the subset of required permissions the user does not have."""
    if isinstance(required, str):
        required = [required]

    return [perm for perm in required if perm not in user_permissions]
