"""Identity fields: usernames stay with their owner, email changes are proven by the new mailbox, and emails compare case-insensitively."""

import re
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio
from fastapi import BackgroundTasks, HTTPException
from pydantic import ValidationError

from app.api.v1.endpoints import auth, users
from app.core import security
from app.core.permissions import Permissions
from app.models.system import SystemSettings
from app.models.user import User
from app.repositories.users import IdentityTakenError, UserRepository
from app.schemas import user as user_schemas
from tests.mocks.fake_mongo import FakeDatabase

LOCAL_ID = "u-lena"
IDP_ID = "u-otto"
LEGACY_ID = "u-tara"
ADMIN_ID = "u-admin"

LOCAL = {
    "_id": LOCAL_ID,
    "username": "lena",
    "email": "lena@corp.com",
    "auth_provider": "local",
    "is_verified": False,
    "permissions": [],
}
IDP = {
    "_id": IDP_ID,
    "username": "otto",
    "email": "otto@corp.com",
    "auth_provider": "gitlab",
    "is_verified": True,
    "permissions": [],
}
# Stored before emails were normalised.
LEGACY = {
    "_id": LEGACY_ID,
    "username": "tara",
    "email": "Tara@Corp.com",
    "auth_provider": "local",
    "is_verified": True,
    "permissions": [],
}
ADMIN = {
    "_id": ADMIN_ID,
    "username": "admin",
    "email": "admin@corp.com",
    "auth_provider": "local",
    "is_verified": True,
    "permissions": [Permissions.USER_UPDATE, Permissions.USER_READ_ALL],
}

PASSWORD = "Sup3r!Secret"
MAIL = SystemSettings(smtp_host="smtp.test", allow_public_registration=True)
NO_MAIL = SystemSettings(smtp_host=None, allow_public_registration=True)


@pytest_asyncio.fixture
async def db():
    database = FakeDatabase()
    repo = UserRepository(database)
    for doc in (LOCAL, IDP, LEGACY, ADMIN):
        await repo.create_raw(dict(doc))
    return database


async def _stored(db, user_id):
    return await UserRepository(db).get_raw_by_id(user_id)


def _system(settings):
    return patch("app.api.deps.get_system_settings", new=AsyncMock(return_value=settings))


async def _put(db, caller, target_id, **fields):
    with _system(MAIL):
        return await users.update_user(target_id, user_schemas.UserUpdate(**fields), User(**caller), db)


async def _request_change(db, caller, new_email, settings=MAIL):
    background_tasks = BackgroundTasks()
    with _system(settings):
        result = await users.request_email_change(
            user_schemas.UserEmailChange(email=new_email), background_tasks, User(**caller), db
        )
    return result, background_tasks


def _mailed_token(background_tasks):
    (task,) = background_tasks.tasks
    return task.kwargs["destination"], re.search(r"token=([\w.\-]+)", task.kwargs["message"]).group(1)


class TestProfileUpdate:
    @pytest.mark.parametrize("field", ["username", "email"])
    def test_the_profile_update_does_not_accept_identity_fields(self, field):
        with pytest.raises(ValidationError):
            user_schemas.UserUpdateMe.model_validate({field: "lena2@corp.com"})


class TestUpdateUserIdentityFields:
    @pytest.mark.asyncio
    @pytest.mark.parametrize(("field", "value"), [("username", "lena2"), ("email", "lena2@corp.com")])
    async def test_a_user_cannot_change_their_own_identity_fields(self, db, field, value):
        with pytest.raises(HTTPException) as exc_info:
            await _put(db, LOCAL, LOCAL_ID, **{field: value})

        assert exc_info.value.status_code == 403
        assert await _stored(db, LOCAL_ID) == LOCAL

    @pytest.mark.asyncio
    async def test_an_administrator_cannot_rename_themselves_either(self, db):
        with pytest.raises(HTTPException) as exc_info:
            await _put(db, ADMIN, ADMIN_ID, username="root")

        assert exc_info.value.status_code == 403
        assert (await _stored(db, ADMIN_ID))["username"] == "admin"

    @pytest.mark.asyncio
    async def test_an_administrator_renames_another_user(self, db):
        await _put(db, ADMIN, LOCAL_ID, username="lena2")

        assert (await _stored(db, LOCAL_ID))["username"] == "lena2"

    @pytest.mark.asyncio
    async def test_an_administrator_sets_a_local_email_lowercased_and_unverified(self, db):
        await _put(db, ADMIN, LEGACY_ID, email="Tara.New@Corp.com")

        stored = await _stored(db, LEGACY_ID)
        assert (stored["email"], stored["is_verified"]) == ("tara.new@corp.com", False)

    @pytest.mark.asyncio
    async def test_the_email_of_an_idp_account_is_read_only(self, db):
        with pytest.raises(HTTPException) as exc_info:
            await _put(db, ADMIN, IDP_ID, email="otto.new@corp.com")

        assert exc_info.value.status_code == 400
        assert await _stored(db, IDP_ID) == IDP

    @pytest.mark.asyncio
    async def test_a_case_variant_of_a_registered_email_is_refused(self, db):
        with pytest.raises(IdentityTakenError):
            await _put(db, ADMIN, LOCAL_ID, email="tara@corp.com")

        assert await _stored(db, LOCAL_ID) == LOCAL

    @pytest.mark.asyncio
    async def test_lowercasing_a_users_own_address_keeps_it_verified(self, db):
        await _put(db, ADMIN, LEGACY_ID, email="Tara@Corp.com")

        stored = await _stored(db, LEGACY_ID)
        assert (stored["email"], stored["is_verified"]) == ("tara@corp.com", True)

    @pytest.mark.parametrize("fields", [{"username": "   "}, {"username": None}, {"email": None}])
    def test_identity_fields_cannot_be_blanked(self, fields):
        with pytest.raises(ValidationError):
            user_schemas.UserUpdate.model_validate(fields)

    @pytest.mark.parametrize("field", ["is_active", "permissions"])
    def test_a_field_the_stored_user_requires_cannot_be_written_as_null(self, field):
        with pytest.raises(ValidationError):
            user_schemas.UserUpdate.model_validate({field: None})

    @pytest.mark.parametrize("field", ["slack_username", "mattermost_username", "notification_preferences"])
    def test_a_nullable_field_can_still_be_cleared(self, field):
        cleared = user_schemas.UserUpdate.model_validate({field: None}).model_dump(exclude_unset=True)
        User(username="u", email="u@corp.com", **cleared)


class TestEmailChangeRequest:
    @pytest.mark.asyncio
    async def test_a_local_account_gets_a_pending_address_and_a_link_mailed_to_it(self, db):
        result, background_tasks = await _request_change(db, LOCAL, "Lena.New@Corp.com")

        stored = await _stored(db, LOCAL_ID)
        assert (stored["email"], stored["pending_email"], stored["is_verified"]) == (
            "lena@corp.com",
            "lena.new@corp.com",
            False,
        )
        assert result["pending_email"] == "lena.new@corp.com"
        destination, _ = _mailed_token(background_tasks)
        assert destination == "lena.new@corp.com"

    @pytest.mark.asyncio
    async def test_an_idp_account_cannot_request_one(self, db):
        with pytest.raises(HTTPException) as exc_info:
            await _request_change(db, IDP, "otto.new@corp.com")

        assert exc_info.value.status_code == 400
        assert await _stored(db, IDP_ID) == IDP

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("caller", "new_email", "detail"),
        [
            (LOCAL, "TARA@corp.com", "Email already registered"),
            (LEGACY, "tara@corp.com", "This is already your email address"),
        ],
        ids=["someone-elses", "own"],
    )
    async def test_a_registered_address_in_any_case_is_refused(self, db, caller, new_email, detail):
        with pytest.raises(HTTPException) as exc_info:
            await _request_change(db, caller, new_email)

        assert (exc_info.value.status_code, exc_info.value.detail) == (400, detail)
        assert await _stored(db, caller["_id"]) == caller

    @pytest.mark.asyncio
    async def test_without_a_mail_server_it_is_refused(self, db):
        with pytest.raises(HTTPException) as exc_info:
            await _request_change(db, LOCAL, "lena.new@corp.com", settings=NO_MAIL)

        assert exc_info.value.status_code == 501
        assert await _stored(db, LOCAL_ID) == LOCAL


class TestEmailChangeConfirm:
    @pytest.mark.asyncio
    async def test_the_mailed_link_swaps_in_the_new_address_as_verified(self, db):
        _, background_tasks = await _request_change(db, LOCAL, "lena.new@corp.com")
        _, token = _mailed_token(background_tasks)

        await auth.confirm_email_change(token, db)

        stored = await _stored(db, LOCAL_ID)
        assert (stored["email"], stored["pending_email"], stored["is_verified"]) == ("lena.new@corp.com", None, True)

    @pytest.mark.asyncio
    async def test_a_link_for_a_superseded_request_is_refused(self, db):
        _, first = await _request_change(db, LOCAL, "lena.first@corp.com")
        await _request_change(db, LOCAL, "lena.second@corp.com")

        with pytest.raises(HTTPException) as exc_info:
            await auth.confirm_email_change(_mailed_token(first)[1], db)

        assert exc_info.value.status_code == 400
        stored = await _stored(db, LOCAL_ID)
        assert (stored["email"], stored["pending_email"]) == ("lena@corp.com", "lena.second@corp.com")

    @pytest.mark.asyncio
    async def test_a_link_works_only_once(self, db):
        _, background_tasks = await _request_change(db, LOCAL, "lena.new@corp.com")
        _, token = _mailed_token(background_tasks)
        await auth.confirm_email_change(token, db)

        with pytest.raises(HTTPException) as exc_info:
            await auth.confirm_email_change(token, db)

        assert exc_info.value.status_code == 400

    @pytest.mark.asyncio
    async def test_a_link_is_refused_once_someone_else_registered_the_address(self, db):
        _, background_tasks = await _request_change(db, LOCAL, "lena.new@corp.com")
        await UserRepository(db).create_raw({"_id": "u-late", "username": "late", "email": "Lena.New@corp.com"})

        with pytest.raises(IdentityTakenError):
            await auth.confirm_email_change(_mailed_token(background_tasks)[1], db)

        assert (await _stored(db, LOCAL_ID))["email"] == "lena@corp.com"

    @pytest.mark.asyncio
    async def test_a_signup_verification_token_does_not_change_an_email(self, db):
        with pytest.raises(HTTPException) as exc_info:
            await auth.confirm_email_change(security.create_email_verification_token("lena@corp.com"), db)

        assert exc_info.value.status_code == 400


class TestCaseInsensitiveEmails:
    @pytest.mark.parametrize(
        "build",
        [
            lambda email: user_schemas.UserCreate(email=email, username="n", password=PASSWORD),
            lambda email: user_schemas.UserSignup(email=email, username="n", password=PASSWORD),
            lambda email: user_schemas.UserUpdate(email=email),
            lambda email: user_schemas.UserEmailChange(email=email),
        ],
        ids=["UserCreate", "UserSignup", "UserUpdate", "UserEmailChange"],
    )
    def test_inbound_emails_are_lowercased(self, build):
        assert build("New.User@Corp.COM").email == "new.user@corp.com"

    @pytest.mark.asyncio
    async def test_signup_refuses_a_case_variant_of_a_registered_email(self, db):
        with _system(NO_MAIL), pytest.raises(IdentityTakenError):
            await auth.create_user(
                BackgroundTasks(),
                user_schemas.UserSignup(email="tara@corp.com", username="tara2", password=PASSWORD),
                db,
            )

    @pytest.mark.asyncio
    async def test_a_user_logs_in_with_their_email_in_any_case(self, db):
        user = await auth._lookup_user_for_login(UserRepository(db), "tara@CORP.com")

        assert user["_id"] == LEGACY_ID

    @pytest.mark.asyncio
    async def test_a_returning_sso_user_whose_provider_capitalises_the_domain_keeps_their_account(self, db):
        """The stored address has its domain lowercased; an exact lookup missed it and the second
        login tried to create the account again, which the unique email index refused with a 500."""
        await _oidc_login(db, email="Max.Mustermann@REWE-Digital.COM", preferred_username="max")
        await _oidc_login(db, email="Max.Mustermann@REWE-Digital.COM", preferred_username="max")

        assert await db.users.count_documents({"username": {"$regex": "^max"}}) == 1


OIDC = SystemSettings(
    oidc_enabled=True,
    oidc_token_endpoint="https://idp.example/token",
    oidc_userinfo_endpoint="https://idp.example/userinfo",
)


async def _oidc_login(db, **claims):
    with (
        _system(OIDC),
        patch("app.api.v1.endpoints.auth._validate_oidc_state", new_callable=AsyncMock),
        patch("app.api.v1.endpoints.auth._fetch_oidc_user_info", new=AsyncMock(return_value=claims)),
    ):
        return await auth.login_oidc_callback(request=MagicMock(), code="code", db=db, state="state")


class TestUsernames:
    """A username is looked up at login before the email, so it must never be empty or read as one."""

    @pytest.mark.parametrize(
        "build",
        [
            lambda username: user_schemas.UserCreate(email="n@corp.com", username=username, password=PASSWORD),
            lambda username: user_schemas.UserSignup(email="n@corp.com", username=username, password=PASSWORD),
            lambda username: user_schemas.UserUpdate(username=username),
        ],
        ids=["UserCreate", "UserSignup", "UserUpdate"],
    )
    @pytest.mark.parametrize("username", ["", "   ", "lena@corp.com"], ids=["empty", "blank", "email-shaped"])
    def test_an_unusable_username_is_refused(self, build, username):
        with pytest.raises(ValidationError):
            build(username)

    def test_a_new_username_is_stored_trimmed(self):
        assert user_schemas.UserSignup(email="n@corp.com", username=" nora ", password=PASSWORD).username == "nora"

    @pytest.mark.asyncio
    @pytest.mark.parametrize("preferred_username", ["lena@corp.com", None, ""], ids=["email-shaped", "null", "empty"])
    async def test_an_sso_account_without_a_usable_preferred_username_is_named_after_its_mailbox(
        self, db, preferred_username
    ):
        await _oidc_login(db, email="Nora.New@corp.com", preferred_username=preferred_username)

        assert (await UserRepository(db).get_raw_by_email("nora.new@corp.com"))["username"] == "Nora.New"


def test_creating_a_user_requires_a_password():
    with pytest.raises(ValidationError):
        user_schemas.UserCreate(email="n@corp.com", username="n")
