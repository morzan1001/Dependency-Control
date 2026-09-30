"""Account security mails go out whenever the stored system settings can deliver mail."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pyotp
import pytest
from fastapi import BackgroundTasks

from app.api.v1.endpoints import users
from app.core import security
from app.core.permissions import Permissions
from app.models.system import SystemSettings
from app.models.user import User
from app.schemas.user import User2FADisable, User2FAVerify, UserPasswordUpdate

MODULE = "app.api.v1.endpoints.users"
CONFIGURED = SystemSettings(smtp_host="smtp.corp", emails_from_email="dc@corp.example")
UNCONFIGURED = SystemSettings(smtp_host=None)
PASSWORD = "Current-Passw0rd!"
SECRET = pyotp.random_base32()
ADMIN = User(id="admin-1", username="admin", email="admin@corp.example", permissions=[Permissions.SYSTEM_MANAGE])


def _user_doc() -> dict:
    return {
        "_id": "user-1",
        "username": "alice",
        "email": "alice@corp.example",
        "hashed_password": security.get_password_hash(PASSWORD),
        "auth_provider": "local",
        "totp_secret": SECRET,
        "totp_enabled": True,
        "permissions": [],
    }


ACTIONS = {
    "password_changed": lambda user, bg: users.update_password_me(
        UserPasswordUpdate(current_password=PASSWORD, new_password="New-Passw0rd!long"), bg, user, MagicMock()
    ),
    "2fa_enabled": lambda user, bg: users.enable_2fa(
        User2FAVerify(code=pyotp.TOTP(SECRET).now(), password=PASSWORD), bg, user, MagicMock()
    ),
    "2fa_disabled": lambda user, bg: users.disable_2fa(User2FADisable(password=PASSWORD), bg, user, MagicMock()),
    "2fa_disabled_by_admin": lambda user, bg: users.admin_disable_2fa("user-1", bg, ADMIN, MagicMock()),
}


def _run(action: str, system_settings: SystemSettings) -> BackgroundTasks:
    doc = _user_doc()
    background_tasks = BackgroundTasks()
    with (
        patch(f"{MODULE}.UserRepository", return_value=MagicMock(update=AsyncMock())),
        patch(f"{MODULE}.get_user_or_404", new=AsyncMock(return_value=doc)),
        patch(f"{MODULE}.fetch_updated_user", new=AsyncMock(return_value=doc)),
        patch(f"{MODULE}.deps.get_system_settings", new=AsyncMock(return_value=system_settings)),
    ):
        asyncio.run(ACTIONS[action](User(**doc), background_tasks))
    return background_tasks


@pytest.mark.parametrize("action", ACTIONS)
def test_the_security_alert_is_queued_to_the_account_owner_when_mail_is_configured(action):
    (task,) = _run(action, CONFIGURED).tasks

    assert task.kwargs["destination"] == "alice@corp.example"
    assert task.kwargs["subject"].startswith("Security Alert: ")
    assert task.kwargs["system_settings"] is CONFIGURED


@pytest.mark.parametrize("action", ACTIONS)
def test_no_security_alert_is_queued_when_mail_is_not_configured(action):
    assert _run(action, UNCONFIGURED).tasks == []


def test_an_admin_reset_reports_the_queued_mail_and_never_returns_the_link():
    background_tasks = BackgroundTasks()
    with (
        patch(f"{MODULE}.get_user_or_404", new=AsyncMock(return_value=_user_doc())),
        patch(f"{MODULE}.deps.get_system_settings", new=AsyncMock(return_value=CONFIGURED)),
    ):
        result = asyncio.run(users.reset_user_password("user-1", background_tasks, ADMIN, MagicMock()))

    (task,) = background_tasks.tasks
    assert result["email_queued"] is True
    assert "token=" not in str(result)
    assert task.kwargs["subject"].startswith("Reset your password")
