"""Project-webhook writes need project membership or the global project write grant on top of the
webhook permission; project:read_all opens a project's webhooks for reading only."""

from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

import pytest
from fastapi import HTTPException

from app.core.constants import PROJECT_ROLE_VIEWER, TEAM_ROLE_MEMBER
from app.core.permissions import Permissions
from app.models.user import User
from app.schemas.webhook import WebhookCreate, WebhookUpdate
from tests.mocks.fake_mongo import FakeDatabase

_PROJECT = "proj-1"
_TEAM = "team-1"
_WEBHOOK = "wh-project"
_HOOK_URL = "https://hooks.example.com/project"
_ATTACKER_URL = "https://attacker.example.com/x"
_TIMESTAMP = datetime(2026, 1, 1, tzinfo=timezone.utc)
_WEBHOOK_WRITE = (Permissions.WEBHOOK_CREATE, Permissions.WEBHOOK_UPDATE, Permissions.WEBHOOK_DELETE)
_FIRE = "app.api.v1.endpoints.webhooks.webhook_service.test_webhook"
_FIRED = {"success": True, "status_code": 200, "error": None, "response_time_ms": 12.0}


def _user(user_id: str, *permissions: str) -> User:
    return User(id=user_id, username=user_id, email=f"{user_id}@test.com", permissions=list(permissions))


async def _seeded() -> FakeDatabase:
    db = FakeDatabase()
    await db.teams.insert_one(
        {
            "_id": _TEAM,
            "name": "Team",
            "members": [{"user_id": "team-member", "role": TEAM_ROLE_MEMBER}],
            "created_at": _TIMESTAMP,
            "updated_at": _TIMESTAMP,
        }
    )
    await db.projects.insert_one(
        {
            "_id": _PROJECT,
            "name": "Project",
            "members": [{"user_id": "project-viewer", "role": PROJECT_ROLE_VIEWER}],
            "team_ids": [_TEAM],
            "created_at": _TIMESTAMP,
        }
    )
    await db.webhooks.insert_one(
        {
            "_id": _WEBHOOK,
            "project_id": _PROJECT,
            "url": _HOOK_URL,
            "events": ["scan_completed"],
            "created_at": _TIMESTAMP,
        }
    )
    return db


# Both gate branches: holding the webhook permissions (write intent) and the project-admin fallback without them.
_READ_ALL_HOLDERS = [
    pytest.param((Permissions.PROJECT_READ_ALL,), id="read_all"),
    pytest.param((Permissions.PROJECT_READ_ALL, *_WEBHOOK_WRITE), id="read_all+webhook_write"),
]


class TestReadAllHolderCannotWrite:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("permissions", _READ_ALL_HOLDERS)
    async def test_cannot_create_a_project_webhook(self, permissions):
        from app.api.v1.endpoints.webhooks import create_webhook

        db = await _seeded()

        with pytest.raises(HTTPException) as exc_info:
            await create_webhook(
                project_id=_PROJECT,
                webhook_in=WebhookCreate(url=_ATTACKER_URL, events=["scan_completed"]),
                current_user=_user("auditor", *permissions),
                db=db,
            )

        assert exc_info.value.status_code == 403
        assert list(db.webhooks._docs) == [_WEBHOOK]

    @pytest.mark.asyncio
    @pytest.mark.parametrize("permissions", _READ_ALL_HOLDERS)
    async def test_cannot_update_a_project_webhook(self, permissions):
        from app.api.v1.endpoints.webhooks import update_webhook

        db = await _seeded()

        with pytest.raises(HTTPException) as exc_info:
            await update_webhook(
                webhook_id=_WEBHOOK,
                webhook_update=WebhookUpdate(url=_ATTACKER_URL),
                current_user=_user("auditor", *permissions),
                db=db,
            )

        assert exc_info.value.status_code == 403
        assert db.webhooks._docs[_WEBHOOK]["url"] == _HOOK_URL

    @pytest.mark.asyncio
    @pytest.mark.parametrize("permissions", _READ_ALL_HOLDERS)
    async def test_cannot_delete_a_project_webhook(self, permissions):
        from app.api.v1.endpoints.webhooks import delete_webhook

        db = await _seeded()

        with pytest.raises(HTTPException) as exc_info:
            await delete_webhook(webhook_id=_WEBHOOK, current_user=_user("auditor", *permissions), db=db)

        assert exc_info.value.status_code == 403
        assert _WEBHOOK in db.webhooks._docs

    @pytest.mark.asyncio
    @pytest.mark.parametrize("permissions", _READ_ALL_HOLDERS)
    async def test_cannot_test_fire_a_project_webhook(self, permissions):
        from app.api.v1.endpoints.webhooks import test_webhook

        db = await _seeded()

        with patch(_FIRE, new_callable=AsyncMock, return_value=_FIRED) as fire:
            with pytest.raises(HTTPException) as exc_info:
                await test_webhook(webhook_id=_WEBHOOK, current_user=_user("auditor", *permissions), db=db)

        assert exc_info.value.status_code == 403
        fire.assert_not_awaited()


class TestReadAllHolderReads:
    @pytest.mark.asyncio
    async def test_lists_and_reads_project_webhooks_with_webhook_read(self):
        from app.api.v1.endpoints.webhooks import get_webhook, list_webhooks

        db = await _seeded()
        reader = _user("auditor", Permissions.PROJECT_READ_ALL, Permissions.WEBHOOK_READ)

        listing = await list_webhooks(project_id=_PROJECT, current_user=reader, db=db)
        webhook = await get_webhook(webhook_id=_WEBHOOK, current_user=reader, db=db)

        assert [item["id"] for item in listing["items"]] == [_WEBHOOK]
        assert webhook.id == _WEBHOOK


# A direct viewer and a plain member of an owning team, which the project sees as a viewer.
_VIEWER_MEMBERS = [pytest.param("project-viewer", id="direct_viewer"), pytest.param("team-member", id="team_member")]


class TestViewerMemberWithWebhookWrite:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("user_id", _VIEWER_MEMBERS)
    async def test_creates_a_project_webhook_with_webhook_create(self, user_id):
        from app.api.v1.endpoints.webhooks import create_webhook

        db = await _seeded()

        created = await create_webhook(
            project_id=_PROJECT,
            webhook_in=WebhookCreate(url="https://hooks.example.com/new", events=["scan_completed"]),
            current_user=_user(user_id, Permissions.PROJECT_READ, Permissions.WEBHOOK_CREATE),
            db=db,
        )

        assert sorted(db.webhooks._docs) == sorted([_WEBHOOK, created.id])
        assert db.webhooks._docs[created.id]["project_id"] == _PROJECT

    @pytest.mark.asyncio
    async def test_updates_test_fires_and_deletes_a_project_webhook(self):
        from app.api.v1.endpoints.webhooks import delete_webhook, test_webhook, update_webhook

        db = await _seeded()
        member = _user("project-viewer", Permissions.PROJECT_READ, *_WEBHOOK_WRITE)

        await update_webhook(
            webhook_id=_WEBHOOK,
            webhook_update=WebhookUpdate(url="https://hooks.example.com/moved"),
            current_user=member,
            db=db,
        )
        moved_url = db.webhooks._docs[_WEBHOOK]["url"]
        with patch(_FIRE, new_callable=AsyncMock, return_value=_FIRED) as fire:
            await test_webhook(webhook_id=_WEBHOOK, current_user=member, db=db)
        await delete_webhook(webhook_id=_WEBHOOK, current_user=member, db=db)

        assert moved_url == "https://hooks.example.com/moved"
        fire.assert_awaited_once()
        assert _WEBHOOK not in db.webhooks._docs


class TestGlobalWriteGrantWithoutMembership:
    @pytest.mark.asyncio
    async def test_manages_project_webhooks(self):
        from app.api.v1.endpoints.webhooks import create_webhook, delete_webhook, update_webhook

        db = await _seeded()
        manager = _user("platform-admin", Permissions.PROJECT_UPDATE, *_WEBHOOK_WRITE)

        created = await create_webhook(
            project_id=_PROJECT,
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
