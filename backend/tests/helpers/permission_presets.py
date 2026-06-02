"""
Test-owned permission presets.

Presets are a FRONTEND concept (the canonical copies live in
``frontend/src/lib/permissions.ts``); the backend runtime does not use them.
These mirrors exist purely so test fixtures can model the real role catalog
without depending on the backend. Keep them in sync with the frontend presets.

``ALL_PERMISSIONS`` is intentionally imported from ``app.core.permissions``:
that constant stays in the backend (used by the bootstrap admin in init_db).
"""

from typing import List

from app.core.permissions import ALL_PERMISSIONS, Permissions

# Admin: All permissions (mirrors frontend PRESET_ADMIN).
PRESET_ADMIN: List[str] = list(ALL_PERMISSIONS)

# Regular User: Can create/manage own projects and teams, view analytics,
# use chat + MCP. Mirrors frontend PRESET_USER exactly.
# Analytics stays own-projects-only (no analytics:global / project:read_all).
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
    # Archives - can view and download archives for accessible projects
    Permissions.ARCHIVE_READ,
    Permissions.ARCHIVE_DOWNLOAD,
    # Chat + MCP for regular users
    Permissions.CHAT_ACCESS,
    Permissions.CHAT_HISTORY_READ,
    Permissions.CHAT_HISTORY_DELETE,
    Permissions.MCP_ACCESS,
]

# Viewer: Read-only access (mirrors frontend PRESET_VIEWER).
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
    # Archives - can view archives
    Permissions.ARCHIVE_READ,
]
