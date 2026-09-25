"""Tests that PUT /users/{id} never sets a password and points each caller to the right flow."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException

from app.core.permissions import Permissions
from app.models.user import User
from app.schemas.user import UserUpdate

MODULE = "app.api.v1.endpoints.users"


def _run_password_update(current_user, target_id):
    from app.api.v1.endpoints.users import update_user

    repo = MagicMock()
    repo.update = AsyncMock()
    with (
        patch(f"{MODULE}.get_user_or_404", new=AsyncMock(return_value={"_id": target_id})),
        patch(f"{MODULE}.UserRepository", return_value=repo),
        pytest.raises(HTTPException) as exc_info,
    ):
        asyncio.run(update_user(target_id, UserUpdate(password="N3w!Passw0rd"), current_user, MagicMock()))
    repo.update.assert_not_called()
    return exc_info.value


def test_an_admin_is_sent_to_the_reset_link_flow():
    admin = User(id="admin-1", username="admin", email="a@test.com", permissions=[Permissions.USER_UPDATE])

    error = _run_password_update(admin, "other-1")

    assert error.status_code == 400
    assert "Reset Password" in error.detail


def test_a_user_changing_their_own_password_is_sent_to_the_me_endpoint():
    user = User(id="self-1", username="self", email="s@test.com", permissions=[])

    error = _run_password_update(user, "self-1")

    assert (error.status_code, error.detail) == (400, "Use the /me/password endpoint to change your password.")
