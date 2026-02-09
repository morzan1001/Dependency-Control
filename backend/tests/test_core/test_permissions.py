"""Tests for the permission system."""

from app.core.permissions import (
    Permissions,
    ALL_PERMISSIONS,
    PRESET_ADMIN,
    PRESET_USER,
    PRESET_VIEWER,
    has_permission,
    get_missing_permissions,
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
                require_all=False,
            )
            is True
        )

    def test_any_mode_none_present(self, viewer_permissions):
        assert (
            has_permission(
                viewer_permissions,
                [Permissions.SYSTEM_MANAGE, Permissions.USER_DELETE],
                require_all=False,
            )
            is False
        )

    def test_all_mode_all_present(self, admin_permissions):
        assert (
            has_permission(
                admin_permissions,
                [Permissions.USER_READ, Permissions.USER_DELETE],
                require_all=True,
            )
            is True
        )

    def test_all_mode_one_missing(self, user_permissions):
        assert (
            has_permission(
                user_permissions,
                [Permissions.USER_READ, Permissions.USER_DELETE],
                require_all=True,
            )
            is False
        )

    def test_empty_user_permissions(self):
        assert has_permission([], Permissions.USER_READ) is False

    def test_string_required_auto_wrapped(self):
        assert has_permission([Permissions.USER_READ], "user:read") is True

    def test_empty_required_list_returns_false(self):
        assert has_permission([Permissions.USER_READ], []) is False


class TestGetMissingPermissions:
    def test_none_missing(self, admin_permissions):
        missing = get_missing_permissions(admin_permissions, ALL_PERMISSIONS)
        assert missing == []

    def test_some_missing(self, viewer_permissions):
        missing = get_missing_permissions(
            viewer_permissions,
            [Permissions.USER_READ, Permissions.USER_DELETE],
        )
        assert Permissions.USER_DELETE in missing
        assert Permissions.USER_READ not in missing

    def test_string_required(self):
        missing = get_missing_permissions([], "user:read")
        assert missing == ["user:read"]

    def test_all_missing(self):
        missing = get_missing_permissions(
            [],
            [Permissions.USER_READ, Permissions.USER_DELETE],
        )
        assert len(missing) == 2


class TestPresets:
    def test_admin_has_all_permissions(self):
        assert set(PRESET_ADMIN) == set(ALL_PERMISSIONS)

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

    def test_all_permissions_count(self):
        # Ensure consistency between Permissions class and ALL_PERMISSIONS list
        perm_attrs = [v for k, v in vars(Permissions).items() if not k.startswith("_") and isinstance(v, str)]
        assert set(perm_attrs) == set(ALL_PERMISSIONS)
