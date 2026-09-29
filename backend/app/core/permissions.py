"""Centralized fine-grained permission constants and helpers (no wildcard permissions).

Project access composes two layers — global permissions (this module) and ordered project
roles (viewer < editor < admin) — enforced by ``check_project_access`` in
``app/api/v1/helpers/projects.py``. Canonical model: ``docs/superpowers/specs/authz-model.md``.
"""


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

    # Ad-hoc analysis (stateless /analyze endpoint)
    ANALYZE_ADHOC = "analyze:adhoc"


# auth:setup_2fa is an internal marker, not a grantable permission, so it is not a class attribute.
ALL_PERMISSIONS: list[str] = [v for k, v in vars(Permissions).items() if k.isupper()]


def has_permission(user_permissions: list[str], required: str | list[str]) -> bool:
    """Whether the user holds ANY of the required permissions."""
    if isinstance(required, str):
        required = [required]
    return any(perm in user_permissions for perm in required)
