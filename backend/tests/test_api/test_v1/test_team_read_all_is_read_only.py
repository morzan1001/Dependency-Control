"""team:read_all opens every team for reading and none for writing; the global write grants
(team:update, team:delete) keep working without membership."""

from datetime import datetime, timezone

import pytest
from fastapi import HTTPException

from app.core.constants import TEAM_ROLE_ADMIN, TEAM_ROLE_MEMBER
from app.core.permissions import Permissions
from app.models.user import User
from app.schemas.team import TeamMemberAdd, TeamMemberUpdate
from app.schemas.webhook import WebhookCreate, WebhookUpdate
from tests.mocks.fake_mongo import FakeDatabase

_TEAM = "team-1"
_WEBHOOK = "wh-team"
_HOOK_URL = "https://hooks.example.com/team"
_TIMESTAMP = datetime(2026, 1, 1, tzinfo=timezone.utc)
_WEBHOOK_WRITE = (Permissions.WEBHOOK_CREATE, Permissions.WEBHOOK_UPDATE, Permissions.WEBHOOK_DELETE)


def _outsider(*permissions: str) -> User:
    return User(id="outsider", username="outsider", email="outsider@test.com", permissions=list(permissions))


async def _seeded() -> FakeDatabase:
    db = FakeDatabase()
    await db.teams.insert_one(
        {
            "_id": _TEAM,
            "name": "Team",
            "members": [
                {"user_id": "team-admin", "role": TEAM_ROLE_ADMIN},
                {"user_id": "team-member", "role": TEAM_ROLE_MEMBER},
            ],
            "created_at": _TIMESTAMP,
            "updated_at": _TIMESTAMP,
        }
    )
    for user_id in ("team-admin", "team-member", "outsider"):
        await db.users.insert_one({"_id": user_id, "username": user_id, "email": f"{user_id}@test.com"})
    await db.webhooks.insert_one(
        {"_id": _WEBHOOK, "team_id": _TEAM, "url": _HOOK_URL, "events": ["scan_completed"], "created_at": _TIMESTAMP}
    )
    return db


def _roles(db: FakeDatabase) -> dict[str, str]:
    return {m["user_id"]: m["role"] for m in db.teams._docs[_TEAM]["members"]}


_UNTOUCHED_ROLES = {"team-admin": TEAM_ROLE_ADMIN, "team-member": TEAM_ROLE_MEMBER}

# Both gate branches: holding the webhook permission (write intent) and the team-admin fallback without it.
_READ_ALL_HOLDERS = [
    pytest.param((Permissions.TEAM_READ_ALL,), id="read_all"),
    pytest.param((Permissions.TEAM_READ_ALL, *_WEBHOOK_WRITE), id="read_all+webhook_write"),
]


class TestReadAllHolderReads:
    @pytest.mark.asyncio
    async def test_reads_the_team_without_membership(self):
        from app.api.v1.endpoints.teams import read_team

        db = await _seeded()

        team = await read_team(team_id=_TEAM, current_user=_outsider(Permissions.TEAM_READ_ALL), db=db)

        assert team["_id"] == _TEAM

    @pytest.mark.asyncio
    async def test_reads_a_team_webhook_with_webhook_read(self):
        from app.api.v1.endpoints.webhooks import get_webhook

        db = await _seeded()
        reader = _outsider(Permissions.TEAM_READ_ALL, Permissions.WEBHOOK_READ)

        webhook = await get_webhook(webhook_id=_WEBHOOK, current_user=reader, db=db)

        assert webhook.id == _WEBHOOK


class TestReadAllHolderCannotWrite:
    @pytest.mark.asyncio
    async def test_cannot_add_themselves_as_admin(self):
        from app.api.v1.endpoints.teams import add_team_member

        db = await _seeded()

        with pytest.raises(HTTPException) as exc_info:
            await add_team_member(
                team_id=_TEAM,
                member_in=TeamMemberAdd(email="outsider@test.com", role=TEAM_ROLE_ADMIN),
                current_user=_outsider(Permissions.TEAM_READ_ALL),
                db=db,
            )

        assert exc_info.value.status_code == 403
        assert _roles(db) == _UNTOUCHED_ROLES

    @pytest.mark.asyncio
    async def test_cannot_change_a_member_role(self):
        from app.api.v1.endpoints.teams import update_team_member

        db = await _seeded()

        with pytest.raises(HTTPException) as exc_info:
            await update_team_member(
                team_id=_TEAM,
                user_id="team-member",
                member_in=TeamMemberUpdate(role=TEAM_ROLE_ADMIN),
                current_user=_outsider(Permissions.TEAM_READ_ALL),
                db=db,
            )

        assert exc_info.value.status_code == 403
        assert _roles(db) == _UNTOUCHED_ROLES

    @pytest.mark.asyncio
    async def test_cannot_delete_the_team(self):
        from app.api.v1.endpoints.teams import delete_team

        db = await _seeded()

        with pytest.raises(HTTPException) as exc_info:
            await delete_team(team_id=_TEAM, current_user=_outsider(Permissions.TEAM_READ_ALL), db=db)

        assert exc_info.value.status_code == 403
        assert _TEAM in db.teams._docs
        assert _WEBHOOK in db.webhooks._docs

    @pytest.mark.asyncio
    @pytest.mark.parametrize("permissions", _READ_ALL_HOLDERS)
    async def test_cannot_create_a_team_webhook(self, permissions):
        from app.api.v1.endpoints.webhooks import create_team_webhook

        db = await _seeded()

        with pytest.raises(HTTPException) as exc_info:
            await create_team_webhook(
                team_id=_TEAM,
                webhook_in=WebhookCreate(url="https://attacker.example.com/x", events=["scan_completed"]),
                current_user=_outsider(*permissions),
                db=db,
            )

        assert exc_info.value.status_code == 403
        assert list(db.webhooks._docs) == [_WEBHOOK]

    @pytest.mark.asyncio
    @pytest.mark.parametrize("permissions", _READ_ALL_HOLDERS)
    async def test_cannot_update_a_team_webhook(self, permissions):
        from app.api.v1.endpoints.webhooks import update_webhook

        db = await _seeded()

        with pytest.raises(HTTPException) as exc_info:
            await update_webhook(
                webhook_id=_WEBHOOK,
                webhook_update=WebhookUpdate(url="https://attacker.example.com/x"),
                current_user=_outsider(*permissions),
                db=db,
            )

        assert exc_info.value.status_code == 403
        assert db.webhooks._docs[_WEBHOOK]["url"] == _HOOK_URL

    @pytest.mark.asyncio
    @pytest.mark.parametrize("permissions", _READ_ALL_HOLDERS)
    async def test_cannot_delete_a_team_webhook(self, permissions):
        from app.api.v1.endpoints.webhooks import delete_webhook

        db = await _seeded()

        with pytest.raises(HTTPException) as exc_info:
            await delete_webhook(webhook_id=_WEBHOOK, current_user=_outsider(*permissions), db=db)

        assert exc_info.value.status_code == 403
        assert _WEBHOOK in db.webhooks._docs


class TestMemberWithWebhookWrite:
    @pytest.mark.asyncio
    async def test_a_plain_member_manages_team_webhooks(self):
        from app.api.v1.endpoints.webhooks import create_team_webhook, delete_webhook

        db = await _seeded()
        member = User(
            id="team-member",
            username="team-member",
            email="team-member@test.com",
            permissions=[Permissions.TEAM_READ, *_WEBHOOK_WRITE],
        )

        created = await create_team_webhook(
            team_id=_TEAM,
            webhook_in=WebhookCreate(url="https://hooks.example.com/new", events=["scan_completed"]),
            current_user=member,
            db=db,
        )
        await delete_webhook(webhook_id=_WEBHOOK, current_user=member, db=db)

        assert list(db.webhooks._docs) == [created.id]


class TestGlobalWriteGrantsWithoutMembership:
    @pytest.mark.asyncio
    async def test_team_update_adds_a_member(self):
        from app.api.v1.endpoints.teams import add_team_member

        db = await _seeded()
        await db.users.insert_one(
            {"_id": "newcomer", "username": "newcomer", "email": "newcomer@test.com", "is_verified": True}
        )

        await add_team_member(
            team_id=_TEAM,
            member_in=TeamMemberAdd(email="newcomer@test.com"),
            current_user=_outsider(Permissions.TEAM_UPDATE),
            db=db,
        )

        assert _roles(db) == {**_UNTOUCHED_ROLES, "newcomer": TEAM_ROLE_MEMBER}

    @pytest.mark.asyncio
    async def test_team_update_changes_an_admin_role(self):
        from app.api.v1.endpoints.teams import update_team_member

        db = await _seeded()

        await update_team_member(
            team_id=_TEAM,
            user_id="team-admin",
            member_in=TeamMemberUpdate(role=TEAM_ROLE_MEMBER),
            current_user=_outsider(Permissions.TEAM_UPDATE),
            db=db,
        )

        assert _roles(db)["team-admin"] == TEAM_ROLE_MEMBER

    @pytest.mark.asyncio
    async def test_team_update_removes_an_admin(self):
        from app.api.v1.endpoints.teams import remove_team_member

        db = await _seeded()
        await db.teams.update_one(
            {"_id": _TEAM}, {"$push": {"members": {"user_id": "second-admin", "role": TEAM_ROLE_ADMIN}}}
        )

        await remove_team_member(
            team_id=_TEAM, user_id="team-admin", current_user=_outsider(Permissions.TEAM_UPDATE), db=db
        )

        assert _roles(db) == {"team-member": TEAM_ROLE_MEMBER, "second-admin": TEAM_ROLE_ADMIN}

    @pytest.mark.asyncio
    async def test_team_delete_deletes_the_team(self):
        from app.api.v1.endpoints.teams import delete_team

        db = await _seeded()

        await delete_team(team_id=_TEAM, current_user=_outsider(Permissions.TEAM_DELETE), db=db)

        assert _TEAM not in db.teams._docs

    @pytest.mark.asyncio
    async def test_team_update_with_webhook_write_manages_team_webhooks(self):
        from app.api.v1.endpoints.webhooks import create_team_webhook, delete_webhook, update_webhook

        db = await _seeded()
        manager = _outsider(Permissions.TEAM_UPDATE, *_WEBHOOK_WRITE)

        created = await create_team_webhook(
            team_id=_TEAM,
            webhook_in=WebhookCreate(url="https://hooks.example.com/new", events=["scan_completed"]),
            current_user=manager,
            db=db,
        )
        await update_webhook(
            webhook_id=_WEBHOOK,
            webhook_update=WebhookUpdate(url="https://hooks.example.com/moved"),
            current_user=manager,
            db=db,
        )
        await delete_webhook(webhook_id=created.id, current_user=manager, db=db)

        assert list(db.webhooks._docs) == [_WEBHOOK]
        assert db.webhooks._docs[_WEBHOOK]["url"] == "https://hooks.example.com/moved"
