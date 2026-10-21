import logging
import re
from unittest.mock import AsyncMock, MagicMock, patch

import pyotp
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
from app.schemas.user import UserResponse
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
MAIL_ENFORCED = MAIL.model_copy(update={"enforce_email_verification": True})
NO_MAIL_ENFORCED = NO_MAIL.model_copy(update={"enforce_email_verification": True})


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


async def _patch_me(db, caller, **fields):
    return await users.update_user_me(user_schemas.UserUpdateMe(**fields), User(**caller), db)


async def _admin_put(db, target, **fields):
    return await _put(db, ADMIN, target["_id"], **fields)


def _renames(caplog):
    return [r.getMessage() for r in caplog.records if r.levelno == logging.INFO and " renamed " in r.getMessage()]


async def _change_email(db, caller, new_email, settings=MAIL):
    background_tasks = BackgroundTasks()
    with _system(settings):
        result = await users.change_email(
            user_schemas.UserEmailChange(email=new_email), background_tasks, User(**caller), db
        )
    return result, background_tasks


def _mailed_token(background_tasks):
    (task,) = background_tasks.tasks
    return task.kwargs["destination"], re.search(r"token=([\w.\-]+)", task.kwargs["message"]).group(1)


class TestProfileUpdate:
    def test_the_profile_update_does_not_accept_an_email(self):
        with pytest.raises(ValidationError):
            user_schemas.UserUpdateMe.model_validate({"email": "lena2@corp.com"})

    @pytest.mark.parametrize("username", ["", "   ", None], ids=["empty", "blank", "null"])
    def test_the_profile_update_cannot_blank_the_username(self, username):
        with pytest.raises(ValidationError):
            user_schemas.UserUpdateMe.model_validate({"username": username})


class TestRenames:
    @pytest.mark.asyncio
    async def test_a_user_renames_themselves_from_the_profile(self, db, caplog):
        with caplog.at_level(logging.INFO):
            result = await _patch_me(db, LOCAL, username="lena.k")

        assert (await _stored(db, LOCAL_ID))["username"] == result.username == "lena.k"
        assert _renames(caplog) == [f"User {LOCAL_ID} renamed user {LOCAL_ID} from 'lena' to 'lena.k'"]

    @pytest.mark.asyncio
    async def test_an_identity_provider_account_renames_itself_too(self, db):
        await _patch_me(db, IDP, username="otto.k")

        assert (await _stored(db, IDP_ID))["username"] == "otto.k"

    @pytest.mark.asyncio
    async def test_an_administrator_renames_another_user(self, db, caplog):
        with caplog.at_level(logging.INFO):
            await _put(db, ADMIN, LOCAL_ID, username="lena2")

        assert (await _stored(db, LOCAL_ID))["username"] == "lena2"
        assert _renames(caplog) == [f"User {ADMIN_ID} renamed user {LOCAL_ID} from 'lena' to 'lena2'"]

    @pytest.mark.asyncio
    async def test_an_administrator_renames_themselves(self, db, caplog):
        with caplog.at_level(logging.INFO):
            await _put(db, ADMIN, ADMIN_ID, username="root")

        assert (await _stored(db, ADMIN_ID))["username"] == "root"
        assert _renames(caplog) == [f"User {ADMIN_ID} renamed user {ADMIN_ID} from 'admin' to 'root'"]

    @pytest.mark.asyncio
    async def test_an_administrator_cannot_rename_a_user_who_holds_permissions_they_lack(self, db):
        boss = {**ADMIN, "_id": "u-boss", "username": "boss", "email": "boss@corp.com"}
        boss["permissions"] = [*ADMIN["permissions"], Permissions.SYSTEM_MANAGE]
        await UserRepository(db).create_raw(dict(boss))

        with pytest.raises(HTTPException) as exc_info:
            await _put(db, ADMIN, "u-boss", username="minion")

        assert exc_info.value.status_code == 403
        assert (await _stored(db, "u-boss"))["username"] == "boss"

    @pytest.mark.asyncio
    @pytest.mark.parametrize("username", ["ab", "a" * 64, "Lena_K-1.2", "0lena", "Lena Kraft", "Anna Lena Kraft"])
    async def test_a_name_within_the_rule_is_taken(self, db, username):
        await _patch_me(db, LOCAL, username=username)

        assert (await _stored(db, LOCAL_ID))["username"] == username

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "username",
        ["l", "a" * 65, "-lena", ".lena", "_lena", "lena@corp.com", "lena  k", "lena\tk", "jörg", "lena/k"],
        ids=[
            "short",
            "long",
            "hyphen-first",
            "dot-first",
            "underscore-first",
            "email",
            "double-space",
            "tab",
            "umlaut",
            "slash",
        ],
    )
    @pytest.mark.parametrize("rename", [_patch_me, _admin_put], ids=["profile", "admin"])
    async def test_a_new_name_outside_the_rule_is_refused(self, db, rename, username):
        with pytest.raises(HTTPException) as exc_info:
            await rename(db, LOCAL, username=username)

        assert exc_info.value.status_code == 422
        assert await _stored(db, LOCAL_ID) == LOCAL

    @pytest.mark.asyncio
    @pytest.mark.parametrize("rename", [_patch_me, _admin_put], ids=["profile", "admin"])
    async def test_another_accounts_name_in_any_case_is_refused(self, db, rename):
        with pytest.raises(IdentityTakenError, match="Username already taken"):
            await rename(db, LOCAL, username="OTTO")

        assert await _stored(db, LOCAL_ID) == LOCAL

    @pytest.mark.asyncio
    async def test_a_user_changes_the_case_of_their_own_name(self, db):
        await _patch_me(db, LOCAL, username="Lena")

        assert (await _stored(db, LOCAL_ID))["username"] == "Lena"

    @pytest.mark.asyncio
    async def test_an_unchanged_name_outside_the_rule_stays_valid(self, db, caplog):
        legacy = {**LOCAL, "_id": "u-nora", "username": "Nora Neu", "email": "nora@corp.com"}
        await UserRepository(db).create_raw(dict(legacy))

        with caplog.at_level(logging.INFO):
            await _patch_me(db, legacy, username="Nora Neu", slack_username="U1")
            await _put(db, ADMIN, "u-nora", username="Nora Neu", is_active=False)

        stored = await _stored(db, "u-nora")
        assert (stored["username"], stored["slack_username"], stored["is_active"]) == ("Nora Neu", "U1", False)
        assert _renames(caplog) == []

    @pytest.mark.asyncio
    async def test_a_new_name_and_chat_ids_save_in_one_profile_request(self, db):
        changes = {"username": "lena.k", "slack_username": "U1", "mattermost_username": "lena-mm"}
        await _patch_me(db, LOCAL, **changes)

        stored = await _stored(db, LOCAL_ID)
        assert {field: stored[field] for field in changes} == changes

    @pytest.mark.asyncio
    async def test_a_refused_name_leaves_the_chat_ids_of_its_request_unsaved(self, db):
        with pytest.raises(IdentityTakenError):
            await _patch_me(db, LOCAL, username="otto", slack_username="U1")

        assert await _stored(db, LOCAL_ID) == LOCAL


class TestUpdateUserIdentityFields:
    @pytest.mark.asyncio
    async def test_a_user_cannot_change_their_own_email_here(self, db):
        with pytest.raises(HTTPException) as exc_info:
            await _put(db, LOCAL, LOCAL_ID, email="lena2@corp.com")

        assert exc_info.value.status_code == 403
        assert await _stored(db, LOCAL_ID) == LOCAL

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


class TestEmailChange:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("settings", [MAIL, MAIL_ENFORCED], ids=["mail", "mail-verification-enforced"])
    async def test_with_a_mail_server_the_new_address_waits_for_the_link_mailed_to_it(self, db, settings):
        result, background_tasks = await _change_email(db, LEGACY, "Tara.New@Corp.com", settings)

        stored = await _stored(db, LEGACY_ID)
        assert (stored["email"], stored["pending_email"], stored["is_verified"]) == (
            "Tara@Corp.com",
            "tara.new@corp.com",
            True,
        )
        assert (result["pending_email"], result["email_change"]) == ("tara.new@corp.com", "pending_confirmation")
        destination, _ = _mailed_token(background_tasks)
        assert destination == "tara.new@corp.com"

    @pytest.mark.asyncio
    async def test_without_a_mail_server_the_new_address_applies_at_once_unverified(self, db):
        result, background_tasks = await _change_email(db, LEGACY, "Tara.New@Corp.com", NO_MAIL)

        stored = await _stored(db, LEGACY_ID)
        assert (stored["email"], stored["pending_email"], stored["is_verified"]) == ("tara.new@corp.com", None, False)
        assert (result["email"], result["is_verified"], result["email_change"]) == (
            "tara.new@corp.com",
            False,
            "changed",
        )
        assert background_tasks.tasks == []

    @pytest.mark.asyncio
    async def test_without_a_mail_server_an_earlier_pending_change_and_its_link_are_dropped(self, db):
        _, mailed = await _change_email(db, LOCAL, "lena.first@corp.com")
        await _change_email(db, LOCAL, "lena.second@corp.com", NO_MAIL)

        with pytest.raises(HTTPException) as exc_info:
            await auth.confirm_email_change(_mailed_token(mailed)[1], db)

        assert exc_info.value.status_code == 400
        stored = await _stored(db, LOCAL_ID)
        assert (stored["email"], stored["pending_email"]) == ("lena.second@corp.com", None)

    @pytest.mark.asyncio
    async def test_with_verification_enforced_and_no_mail_server_the_change_is_refused(self, db):
        with pytest.raises(HTTPException) as exc_info:
            await _change_email(db, LEGACY, "tara.new@corp.com", NO_MAIL_ENFORCED)

        assert (exc_info.value.status_code, exc_info.value.detail) == (
            501,
            "Email verification is required, but no mail server is configured to confirm a new address",
        )
        assert await _stored(db, LEGACY_ID) == LEGACY

    @pytest.mark.asyncio
    @pytest.mark.parametrize("settings", [MAIL, NO_MAIL], ids=["mail", "no-mail"])
    async def test_an_idp_account_cannot_change_it(self, db, settings):
        with pytest.raises(HTTPException) as exc_info:
            await _change_email(db, IDP, "otto.new@corp.com", settings)

        assert exc_info.value.status_code == 400
        assert await _stored(db, IDP_ID) == IDP

    @pytest.mark.asyncio
    @pytest.mark.parametrize("settings", [MAIL, NO_MAIL], ids=["mail", "no-mail"])
    async def test_someone_elses_address_in_any_case_is_refused(self, db, settings):
        with pytest.raises(IdentityTakenError, match="Email already registered"):
            await _change_email(db, LOCAL, "TARA@corp.com", settings)

        assert await _stored(db, LOCAL_ID) == LOCAL

    @pytest.mark.asyncio
    @pytest.mark.parametrize("settings", [MAIL, NO_MAIL], ids=["mail", "no-mail"])
    async def test_the_own_address_in_any_case_is_refused(self, db, settings):
        with pytest.raises(HTTPException) as exc_info:
            await _change_email(db, LEGACY, "tara@corp.com", settings)

        assert (exc_info.value.status_code, exc_info.value.detail) == (400, "This is already your email address")
        assert await _stored(db, LEGACY_ID) == LEGACY


class TestEmailChangeConfirm:
    @pytest.mark.asyncio
    async def test_the_mailed_link_swaps_in_the_new_address_as_verified(self, db):
        _, background_tasks = await _change_email(db, LOCAL, "lena.new@corp.com")
        _, token = _mailed_token(background_tasks)

        await auth.confirm_email_change(token, db)

        stored = await _stored(db, LOCAL_ID)
        assert (stored["email"], stored["pending_email"], stored["is_verified"]) == ("lena.new@corp.com", None, True)

    @pytest.mark.asyncio
    async def test_a_link_for_a_superseded_request_is_refused(self, db):
        _, first = await _change_email(db, LOCAL, "lena.first@corp.com")
        await _change_email(db, LOCAL, "lena.second@corp.com")

        with pytest.raises(HTTPException) as exc_info:
            await auth.confirm_email_change(_mailed_token(first)[1], db)

        assert exc_info.value.status_code == 400
        stored = await _stored(db, LOCAL_ID)
        assert (stored["email"], stored["pending_email"]) == ("lena@corp.com", "lena.second@corp.com")

    @pytest.mark.asyncio
    async def test_a_link_works_only_once(self, db):
        _, background_tasks = await _change_email(db, LOCAL, "lena.new@corp.com")
        _, token = _mailed_token(background_tasks)
        await auth.confirm_email_change(token, db)

        with pytest.raises(HTTPException) as exc_info:
            await auth.confirm_email_change(token, db)

        assert exc_info.value.status_code == 400

    @pytest.mark.asyncio
    async def test_a_link_is_refused_once_someone_else_registered_the_address(self, db):
        _, background_tasks = await _change_email(db, LOCAL, "lena.new@corp.com")
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
            lambda email: user_schemas.UserCreate(email=email, username="nora", password=PASSWORD),
            lambda email: user_schemas.UserSignup(email=email, username="nora", password=PASSWORD),
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
        patch("app.api.v1.endpoints.auth._consume_oidc_state", new_callable=AsyncMock),
        patch("app.api.v1.endpoints.auth._fetch_oidc_user_info", new=AsyncMock(return_value=claims)),
    ):
        return await auth.login_oidc_callback(request=MagicMock(), db=db, code="code", state="state")


class TestUsernames:
    """A username is looked up at login before the email, so a chosen one must never be empty or read as one."""

    @pytest.mark.parametrize(
        "build",
        [
            lambda username: user_schemas.UserCreate(email="n@corp.com", username=username, password=PASSWORD),
            lambda username: user_schemas.UserSignup(email="n@corp.com", username=username, password=PASSWORD),
        ],
        ids=["UserCreate", "UserSignup"],
    )
    @pytest.mark.parametrize(
        "username",
        ["", "   ", "n", "a" * 65, "-nora", "nora@corp.com", "nora  k", "jörg"],
        ids=["empty", "blank", "short", "long", "hyphen-first", "email-shaped", "double-space", "umlaut"],
    )
    def test_a_new_account_with_a_name_outside_the_rule_is_refused(self, build, username):
        with pytest.raises(ValidationError):
            build(username)

    def test_a_new_username_is_stored_trimmed(self):
        assert user_schemas.UserSignup(email="n@corp.com", username=" nora ", password=PASSWORD).username == "nora"

    def test_a_new_account_may_take_a_name_in_the_first_and_last_name_style(self):
        assert (
            user_schemas.UserCreate(email="n@corp.com", username="Nora Kraft", password=PASSWORD).username
            == "Nora Kraft"
        )

    @pytest.mark.asyncio
    async def test_an_sso_account_keeps_a_provider_name_outside_the_rule(self, db):
        await _oidc_login(db, email="max@corp.com", preferred_username="Max  Müller")

        assert (await UserRepository(db).get_raw_by_email("max@corp.com"))["username"] == "Max  Müller"

    @pytest.mark.asyncio
    async def test_an_sso_first_login_is_not_refused_for_a_case_variant_of_another_name(self, db):
        await _oidc_login(db, email="lena.idp@corp.com", preferred_username="LENA")

        assert (await UserRepository(db).get_raw_by_email("lena.idp@corp.com"))["username"] == "LENA"

    @pytest.mark.asyncio
    @pytest.mark.parametrize("preferred_username", ["lena@corp.com", None, ""], ids=["email-shaped", "null", "empty"])
    async def test_an_sso_account_without_a_usable_preferred_username_is_named_after_its_mailbox(
        self, db, preferred_username
    ):
        await _oidc_login(db, email="Nora.New@corp.com", preferred_username=preferred_username)

        assert (await UserRepository(db).get_raw_by_email("nora.new@corp.com"))["username"] == "Nora.New"


def test_creating_a_user_requires_a_password():
    with pytest.raises(ValidationError):
        user_schemas.UserCreate(email="n@corp.com", username="nora")


_NEW_PASSWORD = "An0ther!Secret-long"
_TOTP_SECRET = pyotp.random_base32()
_HASHED = {**LOCAL, "hashed_password": security.get_password_hash(PASSWORD), "totp_secret": _TOTP_SECRET}

_MUTATIONS = {
    "update_user_me": lambda db: users.update_user_me(
        user_schemas.UserUpdateMe(slack_username="lena-s"), User(**LOCAL), db
    ),
    "update_user": lambda db: users.update_user(
        LOCAL_ID, user_schemas.UserUpdate(slack_username="lena-s"), User(**ADMIN), db
    ),
    "change_email": lambda db: users.change_email(
        user_schemas.UserEmailChange(email="lena.new@corp.com"), BackgroundTasks(), User(**LOCAL), db
    ),
    "migrate_to_local": lambda db: users.migrate_to_local(
        password_in=user_schemas.UserMigrateToLocal(new_password=_NEW_PASSWORD), current_user=User(**IDP), db=db
    ),
    "migrate_user_to_local": lambda db: users.migrate_user_to_local(IDP_ID, User(**ADMIN), db),
    "update_password_me": lambda db: users.update_password_me(
        user_schemas.UserPasswordUpdate(current_password=PASSWORD, new_password=_NEW_PASSWORD),
        BackgroundTasks(),
        User(**_HASHED),
        db,
    ),
    "enable_2fa": lambda db: users.enable_2fa(
        user_schemas.User2FAVerify(code=pyotp.TOTP(_TOTP_SECRET).now(), password=PASSWORD),
        BackgroundTasks(),
        User(**_HASHED),
        db,
    ),
}


@pytest.mark.asyncio
@pytest.mark.parametrize("mutation", _MUTATIONS)
async def test_a_user_mutation_reads_the_user_back_once_after_its_write(db, mutation):
    """The repository's update already answers with the stored row; a second read only costs a round trip."""
    collection = db.users
    real_find_one, real_update_one = collection.find_one, collection.update_one
    events = []

    async def find_one(*args, **kwargs):
        events.append("read")
        return await real_find_one(*args, **kwargs)

    async def update_one(*args, **kwargs):
        events.append("write")
        return await real_update_one(*args, **kwargs)

    with (
        patch.object(collection, "find_one", find_one),
        patch.object(collection, "update_one", update_one),
        _system(NO_MAIL),
    ):
        result = await _MUTATIONS[mutation](db)

    after_last_write = events[len(events) - events[::-1].index("write") :]
    assert after_last_write == ["read"]
    stored = User(**await _stored(db, result["_id"] if isinstance(result, dict) else result.id))
    assert UserResponse.model_validate(result) == UserResponse.model_validate(stored)
