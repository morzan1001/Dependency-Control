"""Authorization tests for user management: a caller may only act on accounts whose permissions it holds itself, unless it holds system:manage."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import BackgroundTasks, HTTPException

from app.api.v1.endpoints import users
from app.core.config import settings
from app.core.permissions import Permissions
from app.models.system import SystemSettings
from app.models.user import User
from app.schemas.user import UserUpdate

MODULE = "app.api.v1.endpoints.users"
TARGET_ID = "target-1"

DELEGATED_ADMIN = [
    Permissions.USER_READ_ALL,
    Permissions.USER_UPDATE,
    Permissions.USER_DELETE,
    Permissions.USER_MANAGE_PERMISSIONS,
]
SYSTEM_MANAGER = [
    Permissions.SYSTEM_MANAGE,
    Permissions.USER_READ,
    Permissions.USER_UPDATE,
    Permissions.USER_DELETE,
    Permissions.USER_MANAGE_PERMISSIONS,
]

ACTIONS = {
    "update": lambda caller, bg: users.update_user(
        TARGET_ID, UserUpdate(email="takeover@attacker.com"), caller, MagicMock()
    ),
    "migrate": lambda caller, bg: users.migrate_user_to_local(TARGET_ID, caller, MagicMock()),
    "reset_password": lambda caller, bg: users.reset_user_password(TARGET_ID, bg, caller, MagicMock()),
    "disable_2fa": lambda caller, bg: users.admin_disable_2fa(TARGET_ID, bg, caller, MagicMock()),
    "delete": lambda caller, bg: users.delete_user(TARGET_ID, caller, MagicMock()),
}


def _caller(permissions, user_id="caller-1"):
    return User(id=user_id, username="caller", email="caller@test.com", permissions=permissions)


def _target(permissions, auth_provider="local"):
    return {
        "_id": TARGET_ID,
        "username": "target",
        "email": "target@test.com",
        "permissions": permissions,
        "auth_provider": auth_provider,
        "totp_enabled": True,
    }


def _mock_repo(target):
    repo = MagicMock()
    repo.get_raw_by_id = AsyncMock(return_value=target)
    repo.exists_by_email = AsyncMock(return_value=False)
    repo.exists_by_username = AsyncMock(return_value=False)
    repo.update = AsyncMock()
    repo.delete = AsyncMock()
    return repo


def _call(run, target, smtp_host="smtp.test"):
    """Run an endpoint coroutine against a mocked target; return (error, result, repo, background_tasks)."""
    repo = _mock_repo(target)
    background_tasks = BackgroundTasks()
    error = result = None
    with (
        patch(f"{MODULE}.get_user_or_404", new=AsyncMock(return_value=target)),
        patch(f"{MODULE}.fetch_updated_user", new=AsyncMock(return_value=target)),
        patch(f"{MODULE}.UserRepository", return_value=repo),
        patch(f"{MODULE}.deps.get_system_settings", new=AsyncMock(return_value=SystemSettings(smtp_host=smtp_host))),
        patch.object(settings, "SMTP_HOST", None),
    ):
        try:
            result = asyncio.run(run(background_tasks))
        except HTTPException as exc:
            error = exc
    return error, result, repo, background_tasks


def _act(action, caller, target_permissions):
    target = _target(target_permissions, auth_provider="oidc" if action == "migrate" else "local")
    error, _, repo, background_tasks = _call(lambda bg: ACTIONS[action](caller, bg), target)
    acted = bool(repo.update.await_count or repo.delete.await_count or background_tasks.tasks)
    return error, acted


class TestTargetDominance:
    @pytest.mark.parametrize("action", ACTIONS)
    def test_a_delegated_admin_is_refused_against_a_system_admin(self, action):
        error, acted = _act(action, _caller(DELEGATED_ADMIN), [Permissions.SYSTEM_MANAGE, Permissions.USER_UPDATE])

        assert error is not None
        assert error.status_code == 403
        assert not acted

    @pytest.mark.parametrize("action", ACTIONS)
    def test_a_delegated_admin_can_act_on_a_user_it_dominates(self, action):
        error, acted = _act(action, _caller(DELEGATED_ADMIN), [Permissions.USER_READ_ALL])

        assert error is None
        assert acted

    @pytest.mark.parametrize("action", ACTIONS)
    def test_a_system_manager_can_act_on_a_user_holding_permissions_it_lacks(self, action):
        error, acted = _act(action, _caller(SYSTEM_MANAGER), [Permissions.ANALYZE_ADHOC, Permissions.CHAT_ACCESS])

        assert error is None
        assert acted

    def test_editing_your_own_profile_is_not_held_to_the_rule(self):
        # A 2FA-setup session carries fewer permissions than the stored account.
        caller = _caller(["auth:setup_2fa"], user_id=TARGET_ID)
        target = _target([Permissions.PROJECT_READ])

        error, _, repo, _ = _call(
            lambda bg: users.update_user(TARGET_ID, UserUpdate(slack_username="me"), caller, MagicMock()),
            target,
        )

        assert error is None
        repo.update.assert_awaited_once_with(TARGET_ID, {"slack_username": "me"})


def _change_permissions(caller, existing, requested):
    error, _, repo, _ = _call(
        lambda bg: users.update_user(TARGET_ID, UserUpdate(permissions=requested), caller, MagicMock()),
        _target(existing),
    )
    return error, repo


class TestPermissionChanges:
    def test_a_permission_the_caller_lacks_cannot_be_granted(self):
        error, repo = _change_permissions(_caller(SYSTEM_MANAGER), [], [Permissions.ANALYZE_ADHOC])

        assert error is not None
        assert error.status_code == 403
        assert "grant" in error.detail
        repo.update.assert_not_awaited()

    def test_submitting_an_empty_list_cannot_strip_permissions_the_caller_lacks(self):
        error, repo = _change_permissions(
            _caller(SYSTEM_MANAGER), [Permissions.ANALYZE_ADHOC, Permissions.USER_READ], []
        )

        assert error is not None
        assert error.status_code == 403
        assert "revoke" in error.detail
        assert Permissions.ANALYZE_ADHOC in error.detail
        repo.update.assert_not_awaited()

    def test_a_delegated_admin_cannot_empty_a_superiors_permissions(self):
        error, repo = _change_permissions(_caller(DELEGATED_ADMIN), [Permissions.SYSTEM_MANAGE], [])

        assert error is not None
        assert error.status_code == 403
        repo.update.assert_not_awaited()

    def test_keeping_a_permission_the_caller_lacks_is_not_a_grant(self):
        requested = [Permissions.ANALYZE_ADHOC, Permissions.USER_READ]

        error, repo = _change_permissions(_caller(SYSTEM_MANAGER), [Permissions.ANALYZE_ADHOC], requested)

        assert error is None
        repo.update.assert_awaited_once_with(TARGET_ID, {"permissions": requested})


class TestAdminPasswordReset:
    def _reset(self, smtp_host):
        return _call(
            lambda bg: users.reset_user_password(TARGET_ID, bg, _caller(DELEGATED_ADMIN), MagicMock()),
            _target([Permissions.USER_READ_ALL]),
            smtp_host=smtp_host,
        )

    def test_the_reset_link_is_emailed_to_the_user_and_never_returned(self):
        error, result, _, background_tasks = self._reset(smtp_host="smtp.test")

        assert error is None
        assert "token=" not in str(result)
        assert len(background_tasks.tasks) == 1
        email = background_tasks.tasks[0].kwargs
        assert email["destination"] == "target@test.com"
        assert "/reset-password?token=" in email["message"]

    def test_without_a_configured_mail_server_the_reset_is_refused(self):
        error, result, _, background_tasks = self._reset(smtp_host=None)

        assert error is not None
        assert error.status_code == 501
        assert result is None
        assert not background_tasks.tasks
