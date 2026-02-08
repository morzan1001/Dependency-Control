"""Shared fixtures for API endpoint tests."""

import pytest

from app.core.permissions import ALL_PERMISSIONS, PRESET_USER, PRESET_VIEWER
from app.models.user import User


@pytest.fixture
def admin_user():
    """User with all permissions (admin)."""
    return User(
        id="admin-1",
        username="admin",
        email="admin@test.com",
        permissions=list(ALL_PERMISSIONS),
    )


@pytest.fixture
def regular_user():
    """User with standard user permissions."""
    return User(
        id="user-1",
        username="user",
        email="user@test.com",
        permissions=list(PRESET_USER),
    )


@pytest.fixture
def viewer_user():
    """User with viewer-only permissions."""
    return User(
        id="viewer-1",
        username="viewer",
        email="viewer@test.com",
        permissions=list(PRESET_VIEWER),
    )


@pytest.fixture
def no_perms_user():
    """User with zero permissions."""
    return User(
        id="noperm-1",
        username="noperm",
        email="noperm@test.com",
        permissions=[],
    )
