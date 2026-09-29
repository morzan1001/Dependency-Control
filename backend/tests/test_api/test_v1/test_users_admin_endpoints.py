"""The user-administration endpoints: who reaches them, what they accept, and what a deletion takes along."""

import pytest
from fastapi import HTTPException
from pydantic import ValidationError

from app.api.deps import PermissionChecker
from app.api.v1.endpoints import invitations, users
from app.core.permissions import Permissions
from app.models.user import User
from app.schemas.user import UserCreate, UserUpdate
from tests.mocks.fake_mongo import FakeDatabase

ADMIN = User(id="u-admin", username="admin", email="admin@corp.com", permissions=[Permissions.USER_DELETE])


def _required_permissions(router, path: str, method: str) -> list[list[str]]:
    route = next(route for route in router.routes if route.path == path and method in route.methods)
    return [
        dependency.call.required_permissions
        for dependency in route.dependant.dependencies
        if isinstance(dependency.call, PermissionChecker)
    ]


class TestUpdateUser:
    def test_only_a_user_update_holder_reaches_it(self):
        assert _required_permissions(users.router, "/{user_id}", "PUT") == [[Permissions.USER_UPDATE]]

    def test_a_password_is_refused_by_the_schema(self):
        with pytest.raises(ValidationError):
            UserUpdate.model_validate({"password": "N3w!Passw0rd"})


def test_creating_a_user_requires_a_password():
    with pytest.raises(ValidationError):
        UserCreate.model_validate({"email": "new@corp.com", "username": "new"})


class TestRevokeInvitation:
    def test_it_sits_under_the_permission_that_issues_invitations(self):
        assert _required_permissions(invitations.router, "/system/{invitation_id}", "DELETE") == [
            [Permissions.USER_CREATE]
        ]

    @pytest.mark.asyncio
    async def test_a_pending_invitation_is_removed(self):
        db = FakeDatabase()
        await db.system_invitations.insert_one({"_id": "inv-1", "email": "new@corp.com"})

        await invitations.revoke_system_invitation("inv-1", db, ADMIN)

        assert await db.system_invitations.find_one({"_id": "inv-1"}) is None

    @pytest.mark.asyncio
    async def test_an_unknown_id_is_not_found(self):
        with pytest.raises(HTTPException) as exc_info:
            await invitations.revoke_system_invitation("inv-missing", FakeDatabase(), ADMIN)

        assert (exc_info.value.status_code, exc_info.value.detail) == (404, "Invitation not found")


class TestDeleteUser:
    @pytest.mark.asyncio
    async def test_an_invitation_id_is_not_a_user(self):
        db = FakeDatabase()
        await db.system_invitations.insert_one({"_id": "inv-1", "email": "new@corp.com"})

        with pytest.raises(HTTPException) as exc_info:
            await users.delete_user("inv-1", ADMIN, db)

        assert (exc_info.value.status_code, exc_info.value.detail) == (404, "User not found")
        assert await db.system_invitations.find_one({"_id": "inv-1"}) is not None

    @pytest.mark.asyncio
    async def test_the_user_leaves_every_team_and_project(self):
        db = FakeDatabase()
        await db.users.insert_one({"_id": "u-gone", "username": "gone", "email": "g@corp.com", "permissions": []})
        await db.teams.insert_one(
            {
                "_id": "t-1",
                "members": [{"user_id": "u-gone", "role": "admin"}, {"user_id": "u-stay", "role": "admin"}],
            }
        )
        await db.projects.insert_one(
            {
                "_id": "p-1",
                "members": [{"user_id": "u-gone", "role": "admin"}, {"user_id": "u-stay", "role": "viewer"}],
            }
        )

        await users.delete_user("u-gone", ADMIN, db)

        assert await db.users.find_one({"_id": "u-gone"}) is None
        assert [m["user_id"] for m in (await db.teams.find_one({"_id": "t-1"}))["members"]] == ["u-stay"]
        assert [m["user_id"] for m in (await db.projects.find_one({"_id": "p-1"}))["members"]] == ["u-stay"]
