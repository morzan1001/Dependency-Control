"""Authorization tests for create_user (privilege-escalation guard).

Regression coverage for the finding: POST /users/ must not let a caller mint
an account carrying permissions the caller does not itself hold, and setting
any permissions at all requires user:manage_permissions.
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException

from app.core.permissions import Permissions
from app.models.user import User
from app.schemas.user import UserCreate

MODULE = "app.api.v1.endpoints.users"

VALID_PASSWORD = "Str0ng!Passw0rd"


def _helpdesk_user():
    """Caller that can create users but cannot manage permissions."""
    return User(
        id="helpdesk-1",
        username="helpdesk",
        email="helpdesk@test.com",
        permissions=[Permissions.USER_CREATE],
    )


def _perm_manager_user(extra=None):
    """Caller that can create users AND manage permissions (but limited scope)."""
    perms = [Permissions.USER_CREATE, Permissions.USER_MANAGE_PERMISSIONS]
    if extra:
        perms.extend(extra)
    return User(
        id="mgr-1",
        username="mgr",
        email="mgr@test.com",
        permissions=perms,
    )


def _mock_repo():
    repo = MagicMock()
    repo.exists_by_email = AsyncMock(return_value=False)
    repo.exists_by_username = AsyncMock(return_value=False)
    repo.create = AsyncMock()
    return repo


def _run_create(current_user, permissions):
    from app.api.v1.endpoints.users import create_user

    repo = _mock_repo()
    user_in = UserCreate(
        email="new@test.com",
        username="newuser",
        password=VALID_PASSWORD,
        permissions=permissions,
    )
    with patch(f"{MODULE}.UserRepository", return_value=repo):
        result = asyncio.run(create_user(user_in=user_in, current_user=current_user, db=MagicMock()))
    return result, repo


class TestCreateUserPrivilegeEscalation:
    def test_helpdesk_cannot_grant_permissions(self):
        """user:create-only caller cannot set any permissions -> 403, no create."""
        with pytest.raises(HTTPException) as exc:
            _run_create(_helpdesk_user(), [Permissions.SYSTEM_MANAGE])
        assert exc.value.status_code == 403

    def test_manager_cannot_grant_permission_they_lack(self):
        """A manager can manage permissions but not grant one they don't hold."""
        with pytest.raises(HTTPException) as exc:
            _run_create(_perm_manager_user(), [Permissions.SYSTEM_MANAGE])
        assert exc.value.status_code == 403

    def test_manager_can_grant_permission_they_hold(self):
        """Granting a subset of the caller's own permissions is allowed."""
        result, repo = _run_create(
            _perm_manager_user(extra=[Permissions.USER_READ]),
            [Permissions.USER_READ],
        )
        repo.create.assert_called_once()
        assert result.permissions == [Permissions.USER_READ]

    def test_empty_permissions_allowed_for_plain_create(self):
        """A user:create-only caller can still create a user with no permissions."""
        result, repo = _run_create(_helpdesk_user(), [])
        repo.create.assert_called_once()
        assert result.permissions == []
