"""Identity writes over HTTP: a malformed identity is a 422 at the boundary, and an email or username
another account holds is the same 400 on every path, also when only the unique index sees it."""

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch

import pytest

from app.models.user import User
from app.repositories.users import IdentityTakenError, UserRepository

_PASSWORD = "Sup3r!Secret"
_INVITATIONS = "/api/v1/invitations/system"
_LENA = {"_id": "u-lena", "username": "lena", "email": "lena@corp.com", "permissions": []}


async def _with_identity_indexes(db) -> None:
    await db.users.create_index("username", unique=True)
    await db.users.create_index("email", unique=True)
    await db.users.insert_one(dict(_LENA))


@pytest.mark.asyncio
@pytest.mark.parametrize("email", ["bob", "bob@", "@corp.com"])
async def test_a_malformed_invitation_email_is_refused(client, db, admin_auth_headers, email):
    resp = await client.post(_INVITATIONS, json={"email": email}, headers=admin_auth_headers)

    assert resp.status_code == 422, resp.text
    assert await db.system_invitations.count_documents({}) == 0


@pytest.mark.asyncio
async def test_re_inviting_an_address_in_another_case_reuses_the_invitation(client, db, admin_auth_headers):
    first = await client.post(_INVITATIONS, json={"email": "Bob@Corp.COM"}, headers=admin_auth_headers)
    second = await client.post(_INVITATIONS, json={"email": "bob@corp.com"}, headers=admin_auth_headers)

    assert (first.status_code, second.status_code) == (201, 201)
    assert first.json()["link"] == second.json()["link"]
    assert [i["email"] for i in await db.system_invitations.find({}).to_list(None)] == ["bob@corp.com"]


@pytest.mark.asyncio
async def test_inviting_a_registered_address_in_another_case_is_refused(client, db, admin_auth_headers):
    await db.users.insert_one(dict(_LENA))

    resp = await client.post(_INVITATIONS, json={"email": "LENA@corp.com"}, headers=admin_auth_headers)

    assert (resp.status_code, resp.json()["detail"]) == (400, "Email already registered")
    assert await db.system_invitations.count_documents({}) == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("username", ["", "   ", "lena@corp.com"], ids=["empty", "blank", "email-shaped"])
async def test_accepting_an_invitation_with_an_unusable_username_is_refused(client, db, username):
    await db.system_invitations.insert_one(
        {
            "_id": "inv-1",
            "email": "nora@corp.com",
            "token": "tok",
            "invited_by": "admin",
            "is_used": False,
            "expires_at": datetime.now(timezone.utc) + timedelta(days=1),
        }
    )

    resp = await client.post(
        f"{_INVITATIONS}/accept", json={"token": "tok", "username": username, "password": _PASSWORD}
    )

    assert resp.status_code == 422, resp.text
    assert await db.users.count_documents({}) == 0


@pytest.mark.asyncio
async def test_creating_a_user_without_a_password_is_refused_by_the_schema(client, db, admin_auth_headers):
    resp = await client.post(
        "/api/v1/users/", json={"email": "nora@corp.com", "username": "nora"}, headers=admin_auth_headers
    )

    assert resp.status_code == 422, resp.text
    assert await db.users.count_documents({}) == 0


@pytest.mark.live_mongo
@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("body", "detail"),
    [
        ({"email": "nora@corp.com", "username": "lena"}, "Username already taken"),
        ({"email": "Lena@Corp.com", "username": "nora"}, "Email already registered"),
    ],
    ids=["username", "email"],
)
async def test_creating_a_user_with_a_taken_identity_is_refused(client, db, admin_auth_headers, body, detail):
    await _with_identity_indexes(db)

    resp = await client.post("/api/v1/users/", json={**body, "password": _PASSWORD}, headers=admin_auth_headers)

    assert (resp.status_code, resp.json()["detail"]) == (400, detail)
    assert await db.users.count_documents({}) == 1


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_renaming_a_user_to_a_taken_username_is_refused(client, db, admin_auth_headers):
    await _with_identity_indexes(db)
    await db.users.insert_one({"_id": "u-nora", "username": "nora", "email": "nora@corp.com", "permissions": []})

    resp = await client.put("/api/v1/users/u-nora", json={"username": "lena"}, headers=admin_auth_headers)

    assert (resp.status_code, resp.json()["detail"]) == (400, "Username already taken")
    assert (await db.users.find_one({"_id": "u-nora"}))["username"] == "nora"


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_an_email_registered_between_the_check_and_the_insert_is_a_taken_identity(db):
    await _with_identity_indexes(db)
    repo = UserRepository(db)

    with (
        patch.object(repo, "exists_by_email", AsyncMock(return_value=False)),
        pytest.raises(IdentityTakenError, match="Email already registered"),
    ):
        await repo.create(User(username="nora", email="lena@corp.com"))
