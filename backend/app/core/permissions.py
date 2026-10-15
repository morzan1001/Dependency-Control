"""Global permissions without wildcards; check_project_access composes them with the ordered project roles."""

from collections.abc import Sequence


class Permissions:
    SYSTEM_MANAGE = "system:manage"

    USER_CREATE = "user:create"
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

    CHAT_ACCESS = "chat:access"
    CHAT_HISTORY_READ = "chat:history_read"
    CHAT_HISTORY_DELETE = "chat:history_delete"

    MCP_ACCESS = "mcp:access"

    ANALYZE_ADHOC = "analyze:adhoc"

    # The only scope of a session that must enrol in 2FA first; never granted to an account.
    AUTH_SETUP_2FA = "auth:setup_2fa"


ALL_PERMISSIONS: list[str] = [
    v for k, v in vars(Permissions).items() if k.isupper() and v != Permissions.AUTH_SETUP_2FA
]


def is_setup_2fa_scope(permissions: Sequence[str]) -> bool:
    return list(permissions) == [Permissions.AUTH_SETUP_2FA]


def has_permission(user_permissions: list[str], required: str | list[str]) -> bool:
    if isinstance(required, str):
        required = [required]
    return any(perm in user_permissions for perm in required)
