"""A token minted for 2FA enrolment must stay confined to that one scope.

The account behind it keeps its full permissions in the database, so whether the caller can act as
an admin depends entirely on get_current_user preferring the token's scope over the stored one.
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException

from app.api.deps import PermissionChecker, get_current_user
from app.core import security
from app.core.permissions import Permissions

_SETUP_SCOPE = "auth:setup_2fa"
_STORED_PERMISSIONS = [Permissions.SYSTEM_MANAGE, Permissions.PROJECT_CREATE]


def _resolve(token: str):
    user_doc = {
        "_id": "u-1",
        "username": "bob",
        "email": "bob@test.com",
        "is_active": True,
        "permissions": list(_STORED_PERMISSIONS),
    }
    user_repo = MagicMock()
    user_repo.get_raw_by_username = AsyncMock(return_value=user_doc)
    blacklist_repo = MagicMock()
    blacklist_repo.is_blacklisted = AsyncMock(return_value=False)

    with (
        patch("app.api.deps.UserRepository", return_value=user_repo),
        patch("app.repositories.TokenBlacklistRepository", return_value=blacklist_repo),
    ):
        return asyncio.run(get_current_user(db=MagicMock(), token=token))


def test_a_setup_2fa_only_token_drops_the_permissions_stored_on_the_account():
    user = _resolve(security.create_access_token("bob", permissions=[_SETUP_SCOPE]))

    assert user.permissions == [_SETUP_SCOPE]


def test_a_setup_2fa_only_token_is_refused_by_a_permission_guarded_route():
    user = _resolve(security.create_access_token("bob", permissions=[_SETUP_SCOPE]))

    with pytest.raises(HTTPException) as exc_info:
        PermissionChecker(Permissions.SYSTEM_MANAGE)(current_user=user)

    assert exc_info.value.status_code == 403


def test_a_token_carrying_setup_2fa_alongside_other_scopes_keeps_the_stored_permissions():
    """Only the single-scope enrolment token narrows; a wider token must not silently gain the narrowing."""
    token = security.create_access_token("bob", permissions=[_SETUP_SCOPE, Permissions.PROJECT_CREATE])

    user = _resolve(token)

    assert user.permissions == _STORED_PERMISSIONS


def test_an_ordinary_token_keeps_the_permissions_stored_on_the_account():
    user = _resolve(security.create_access_token("bob", permissions=[Permissions.PROJECT_CREATE]))

    assert user.permissions == _STORED_PERMISSIONS
