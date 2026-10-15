"""Mirrors of the frontend presets in frontend/src/lib/permissions.ts; keep them in sync."""

from app.core.permissions import ALL_PERMISSIONS, Permissions

PRESET_ADMIN: list[str] = list(ALL_PERMISSIONS)

PRESET_USER: list[str] = [
    Permissions.TEAM_CREATE,
    Permissions.TEAM_READ,
    Permissions.PROJECT_CREATE,
    Permissions.PROJECT_READ,
    Permissions.ANALYTICS_READ,
    Permissions.ANALYTICS_SUMMARY,
    Permissions.ANALYTICS_DEPENDENCIES,
    Permissions.ANALYTICS_TREE,
    Permissions.ANALYTICS_IMPACT,
    Permissions.ANALYTICS_HOTSPOTS,
    Permissions.ANALYTICS_SEARCH,
    Permissions.ANALYTICS_RECOMMENDATIONS,
    Permissions.WAIVER_READ,
    Permissions.ARCHIVE_READ,
    Permissions.ARCHIVE_DOWNLOAD,
    Permissions.CHAT_ACCESS,
    Permissions.CHAT_HISTORY_READ,
    Permissions.CHAT_HISTORY_DELETE,
    Permissions.MCP_ACCESS,
]

PRESET_VIEWER: list[str] = [
    Permissions.TEAM_READ,
    Permissions.PROJECT_READ,
    Permissions.ANALYTICS_READ,
    Permissions.ANALYTICS_SUMMARY,
    Permissions.WAIVER_READ,
    Permissions.ARCHIVE_READ,
]
