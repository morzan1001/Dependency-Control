"""One rule each for 'this identity is taken' and 'this is a local account', on every path that asks."""

from unittest.mock import AsyncMock, patch

import pytest
import pytest_asyncio
from fastapi import BackgroundTasks, HTTPException
from pydantic import ValidationError

from app.api.v1.endpoints import auth, invitations, users
from app.core.permissions import Permissions
from app.models.system import SystemSettings
from app.models.user import User
from app.repositories.users import UserRepository
from app.schemas import user as user_schemas
from app.schemas.system import SystemSettingsUpdate
from tests.mocks.fake_mongo import FakeDatabase

PASSWORD = "Sup3r!Secret"
TAKEN = {"_id": "u-taken", "username": "taken", "email": "Taken@Corp.com", "auth_provider": "local"}
ADMIN = User(
    id="u-admin",
    username="admin",
    email="admin@corp.com",
    permissions=[Permissions.USER_CREATE, Permissions.USER_UPDATE, Permissions.SYSTEM_MANAGE],
)
EMAIL_TAKEN = (400, "Email already registered")
USERNAME_TAKEN = (400, "Username already taken")


@pytest_asyncio.fixture
async def db():
    database = FakeDatabase()
    await UserRepository(database).create_raw(dict(TAKEN))
    return database


async def _signup(db, **fields):
    settings = SystemSettings(allow_public_registration=True)
    body = {"email": "new@corp.com", "username": "new", "password": PASSWORD} | fields
    with patch("app.api.deps.get_system_settings", new=AsyncMock(return_value=settings)):
        return await auth.create_user(BackgroundTasks(), user_schemas.UserSignup(**body), db)


async def _admin_create(db, **fields):
    body = {"email": "new@corp.com", "username": "new", "password": PASSWORD} | fields
    return await users.create_user(user_schemas.UserCreate(**body), ADMIN, db)


async def _invite(db, email):
    with patch("app.api.deps.get_system_settings", new=AsyncMock(return_value=SystemSettings())):
        return await invitations.create_system_invitation(BackgroundTasks(), db, ADMIN, email)


async def _refusal(call) -> tuple[int, str]:
    with pytest.raises(HTTPException) as exc_info:
        await call
    return exc_info.value.status_code, exc_info.value.detail


class TestOneIdentityRule:
    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("create", "fields", "expected"),
        [
            (_signup, {"email": "taken@corp.com"}, EMAIL_TAKEN),
            (_signup, {"username": "taken"}, USERNAME_TAKEN),
            (_admin_create, {"email": "TAKEN@corp.com"}, EMAIL_TAKEN),
            (_admin_create, {"username": "taken"}, USERNAME_TAKEN),
        ],
        ids=["signup-email", "signup-username", "admin-email", "admin-username"],
    )
    async def test_every_account_creation_refuses_a_taken_identity_alike(self, db, create, fields, expected):
        assert await _refusal(create(db, **fields)) == expected

    @pytest.mark.asyncio
    async def test_an_invitation_to_a_registered_address_is_refused_alike(self, db):
        assert await _refusal(_invite(db, "taken@corp.com")) == EMAIL_TAKEN


class TestAdminCreateSchema:
    def test_an_administrator_cannot_create_an_external_account(self):
        with pytest.raises(ValidationError):
            user_schemas.UserCreate.model_validate(
                {"email": "a@corp.com", "username": "a", "password": PASSWORD, "auth_provider": "GitLab"}
            )

    def test_a_null_active_state_is_refused_at_the_boundary(self):
        with pytest.raises(ValidationError):
            user_schemas.UserCreate.model_validate(
                {"email": "a@corp.com", "username": "a", "password": PASSWORD, "is_active": None}
            )


class TestOneLocalAccountRule:
    @pytest.mark.parametrize(("auth_provider", "local"), [("local", True), ("", True), ("GitLab", False)])
    def test_the_rule(self, auth_provider, local):
        assert User(username="u", email="u@corp.com", auth_provider=auth_provider).is_local is local

    @pytest.mark.asyncio
    async def test_an_account_stored_without_a_provider_name_changes_its_password_like_a_local_one(self, db):
        user = User(
            id="u-blank",
            username="blank",
            email="blank@corp.com",
            auth_provider="",
            hashed_password=users.security.get_password_hash(PASSWORD),
        )
        await UserRepository(db).create(user)
        body = user_schemas.UserPasswordUpdate(current_password=PASSWORD, new_password="An0ther!Secret")

        with patch("app.api.deps.get_system_settings", new=AsyncMock(return_value=SystemSettings())):
            await users.update_password_me(body, BackgroundTasks(), user, db)

        stored = await UserRepository(db).get_raw_by_id("u-blank")
        assert users.security.verify_password("An0ther!Secret", stored["hashed_password"])

    def test_the_oidc_provider_cannot_be_named_like_local_accounts(self):
        with pytest.raises(ValidationError):
            SystemSettingsUpdate(oidc_provider_name="local")

    def test_the_oidc_provider_needs_a_name(self):
        with pytest.raises(ValidationError):
            SystemSettingsUpdate(oidc_provider_name="")
