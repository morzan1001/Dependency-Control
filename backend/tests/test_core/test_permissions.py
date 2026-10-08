"""Tests for the permission system."""

from app.core.permissions import (
    ALL_PERMISSIONS,
    Permissions,
    has_permission,
)
from tests.helpers.permission_presets import (
    PRESET_ADMIN,
    PRESET_USER,
    PRESET_VIEWER,
)


class TestHasPermission:
    def test_single_permission_present(self, admin_permissions):
        assert has_permission(admin_permissions, Permissions.SYSTEM_MANAGE) is True

    def test_single_permission_missing(self, viewer_permissions):
        assert has_permission(viewer_permissions, Permissions.SYSTEM_MANAGE) is False

    def test_any_mode_one_present(self, user_permissions):
        assert (
            has_permission(
                user_permissions,
                [Permissions.SYSTEM_MANAGE, Permissions.PROJECT_READ],
            )
            is True
        )

    def test_any_mode_none_present(self, viewer_permissions):
        assert (
            has_permission(
                viewer_permissions,
                [Permissions.SYSTEM_MANAGE, Permissions.USER_DELETE],
            )
            is False
        )

    def test_empty_user_permissions(self):
        assert has_permission([], Permissions.TEAM_READ) is False

    def test_string_required_auto_wrapped(self):
        assert has_permission([Permissions.TEAM_READ], "team:read") is True

    def test_empty_required_list_returns_false(self):
        assert has_permission([Permissions.TEAM_READ], []) is False


class TestPresets:
    def test_admin_has_all_permissions(self):
        assert set(PRESET_ADMIN) == set(ALL_PERMISSIONS)

    def test_setup_2fa_scope_is_never_grantable(self):
        assert Permissions.AUTH_SETUP_2FA not in ALL_PERMISSIONS

    def test_admin_is_superset_of_user(self):
        assert all(p in PRESET_ADMIN for p in PRESET_USER)

    def test_admin_is_superset_of_viewer(self):
        assert all(p in PRESET_ADMIN for p in PRESET_VIEWER)

    def test_user_is_superset_of_viewer(self):
        assert all(p in PRESET_USER for p in PRESET_VIEWER)

    def test_viewer_cannot_create(self):
        create_perms = [p for p in PRESET_VIEWER if ":create" in p]
        assert create_perms == []

    def test_viewer_cannot_delete(self):
        delete_perms = [p for p in PRESET_VIEWER if ":delete" in p]
        assert delete_perms == []

    def test_admin_preset_is_copy(self):
        # Mutating PRESET_ADMIN should not affect ALL_PERMISSIONS
        admin_copy = PRESET_ADMIN.copy()
        admin_copy.append("test:permission")
        assert "test:permission" not in ALL_PERMISSIONS

    # Archive permission tests
    def test_admin_has_all_archive_permissions(self):
        archive_perms = [
            Permissions.ARCHIVE_READ,
            Permissions.ARCHIVE_RESTORE,
            Permissions.ARCHIVE_DOWNLOAD,
            Permissions.ARCHIVE_READ_ALL,
        ]
        assert all(p in PRESET_ADMIN for p in archive_perms)

    def test_user_has_archive_read_and_download(self):
        assert Permissions.ARCHIVE_READ in PRESET_USER
        assert Permissions.ARCHIVE_DOWNLOAD in PRESET_USER

    def test_user_cannot_restore_archives(self):
        assert Permissions.ARCHIVE_RESTORE not in PRESET_USER

    def test_user_cannot_read_all_archives(self):
        assert Permissions.ARCHIVE_READ_ALL not in PRESET_USER

    def test_viewer_has_archive_read_only(self):
        assert Permissions.ARCHIVE_READ in PRESET_VIEWER
        assert Permissions.ARCHIVE_RESTORE not in PRESET_VIEWER
        assert Permissions.ARCHIVE_DOWNLOAD not in PRESET_VIEWER
        assert Permissions.ARCHIVE_READ_ALL not in PRESET_VIEWER

    # Chat + MCP for regular users
    def test_user_has_chat_and_mcp(self):
        assert Permissions.CHAT_ACCESS in PRESET_USER
        assert Permissions.CHAT_HISTORY_READ in PRESET_USER
        assert Permissions.CHAT_HISTORY_DELETE in PRESET_USER
        assert Permissions.MCP_ACCESS in PRESET_USER

    # Analytics stays own-projects-only: no global analytics / read-all projects
    def test_user_analytics_is_own_projects_only(self):
        assert Permissions.ANALYTICS_GLOBAL not in PRESET_USER
        assert Permissions.PROJECT_READ_ALL not in PRESET_USER

    def test_viewer_has_no_chat_or_mcp(self):
        assert Permissions.CHAT_ACCESS not in PRESET_VIEWER
        assert Permissions.CHAT_HISTORY_READ not in PRESET_VIEWER
        assert Permissions.CHAT_HISTORY_DELETE not in PRESET_VIEWER
        assert Permissions.MCP_ACCESS not in PRESET_VIEWER
