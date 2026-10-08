"""Tests for permission helper functions."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException

from app.api.v1.helpers.projects import check_project_access
from app.api.v1.helpers.teams import check_team_access, get_team_with_access
from app.core.constants import (
    PROJECT_ROLE_ADMIN,
    PROJECT_ROLE_EDITOR,
    PROJECT_ROLE_VIEWER,
    TEAM_ROLE_ADMIN,
    TEAM_ROLE_MEMBER,
)
from app.core.permissions import Permissions
from app.models.user import User
from app.models.webhook import Webhook
from tests.helpers.permission_presets import PRESET_ADMIN, PRESET_USER
from tests.mocks.fake_mongo import FakeDatabase

HELPERS_WEBHOOKS = "app.api.v1.helpers.webhooks"
_ME = "u-1"
_READ = [Permissions.PROJECT_READ]
_READ_ALL = [Permissions.PROJECT_READ, Permissions.PROJECT_READ_ALL]
_UPDATE = [Permissions.PROJECT_READ, Permissions.PROJECT_UPDATE]


def _user(permissions) -> User:
    return User(id=_ME, username=_ME, email=f"{_ME}@test.com", permissions=list(permissions))


async def _run(permissions, *, direct=None, team=None, required_role=None, missing=False):
    db = FakeDatabase()
    if team:
        await db.teams.insert_one({"_id": "team-1", "name": "Team", "members": [{"user_id": _ME, "role": team}]})
    if not missing:
        await db.projects.insert_one(
            {
                "_id": "proj-1",
                "name": "Test",
                "members": [{"user_id": _ME, "role": direct}] if direct else [],
                "team_ids": ["team-1"] if team else [],
            }
        )
    return await check_project_access("proj-1", _user(permissions), db, required_role=required_role)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "permissions, direct, team, required_role",
    [
        (PRESET_ADMIN, None, None, None),
        (PRESET_ADMIN, None, None, PROJECT_ROLE_VIEWER),
        (PRESET_ADMIN, None, None, PROJECT_ROLE_EDITOR),
        (PRESET_ADMIN, None, None, PROJECT_ROLE_ADMIN),
        (_READ_ALL, None, None, None),
        (_READ_ALL, None, None, PROJECT_ROLE_VIEWER),
        (_UPDATE, None, None, None),
        (_UPDATE, None, None, PROJECT_ROLE_EDITOR),
        (_UPDATE, None, None, PROJECT_ROLE_ADMIN),
        (PRESET_USER, PROJECT_ROLE_VIEWER, None, None),
        (PRESET_USER, PROJECT_ROLE_EDITOR, None, PROJECT_ROLE_EDITOR),
        (PRESET_USER, PROJECT_ROLE_ADMIN, None, None),
        (_READ, PROJECT_ROLE_ADMIN, None, PROJECT_ROLE_ADMIN),
        (PRESET_USER, None, TEAM_ROLE_MEMBER, None),
        (PRESET_USER, None, TEAM_ROLE_ADMIN, PROJECT_ROLE_ADMIN),
        (_READ, PROJECT_ROLE_EDITOR, TEAM_ROLE_MEMBER, PROJECT_ROLE_EDITOR),
        (_READ, PROJECT_ROLE_VIEWER, TEAM_ROLE_ADMIN, PROJECT_ROLE_ADMIN),
    ],
)
async def test_check_project_access_grants(permissions, direct, team, required_role):
    assert (await _run(permissions, direct=direct, team=team, required_role=required_role)).id == "proj-1"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "permissions, direct, team, required_role",
    [
        (PRESET_USER, None, None, None),
        ([], PROJECT_ROLE_VIEWER, None, None),
        (_READ_ALL, None, None, PROJECT_ROLE_EDITOR),
        (_READ_ALL, None, None, PROJECT_ROLE_ADMIN),
        (_READ, None, None, PROJECT_ROLE_EDITOR),
        (_READ, None, None, PROJECT_ROLE_ADMIN),
        (PRESET_USER, PROJECT_ROLE_VIEWER, None, PROJECT_ROLE_EDITOR),
        (_READ, PROJECT_ROLE_VIEWER, None, PROJECT_ROLE_ADMIN),
        (PRESET_USER, PROJECT_ROLE_EDITOR, None, PROJECT_ROLE_ADMIN),
        (PRESET_USER, None, TEAM_ROLE_MEMBER, PROJECT_ROLE_EDITOR),
    ],
)
async def test_check_project_access_denies(permissions, direct, team, required_role):
    with pytest.raises(HTTPException) as exc_info:
        await _run(permissions, direct=direct, team=team, required_role=required_role)
    assert exc_info.value.status_code == 403


@pytest.mark.asyncio
async def test_check_project_access_raises_404_for_a_missing_project():
    with pytest.raises(HTTPException) as exc_info:
        await _run(PRESET_USER, missing=True)
    assert exc_info.value.status_code == 404


async def _team_gate(gate, permissions, members, **kwargs):
    db = FakeDatabase()
    if members is not None:
        await db.teams.insert_one(
            {"_id": "team-1", "name": "Team", "members": [{"user_id": uid, "role": role} for uid, role in members]}
        )
    return await gate("team-1", _user(permissions), db, **kwargs)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "gate, permissions, members, kwargs",
    [
        (check_team_access, PRESET_ADMIN, [], {}),
        (check_team_access, PRESET_USER, [(_ME, TEAM_ROLE_MEMBER)], {}),
        (check_team_access, PRESET_USER, [(_ME, TEAM_ROLE_ADMIN)], {"required_role": TEAM_ROLE_ADMIN}),
        (check_team_access, [Permissions.TEAM_READ_ALL], [(_ME, TEAM_ROLE_ADMIN)], {"required_role": TEAM_ROLE_ADMIN}),
        (get_team_with_access, PRESET_ADMIN, [], {}),
        (get_team_with_access, PRESET_USER, [(_ME, TEAM_ROLE_ADMIN)], {}),
    ],
)
async def test_team_gate_grants(gate, permissions, members, kwargs):
    assert (await _team_gate(gate, permissions, members, **kwargs)).id == "team-1"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "gate, permissions, members, kwargs",
    [
        (check_team_access, PRESET_USER, [("other-user", TEAM_ROLE_ADMIN)], {}),
        (check_team_access, PRESET_USER, [(_ME, TEAM_ROLE_MEMBER)], {"required_role": TEAM_ROLE_ADMIN}),
        (check_team_access, [Permissions.TEAM_READ_ALL], [], {"required_role": TEAM_ROLE_MEMBER}),
        (check_team_access, [Permissions.TEAM_READ_ALL], [], {"required_role": TEAM_ROLE_ADMIN}),
        (check_team_access, [], [(_ME, TEAM_ROLE_MEMBER)], {}),
        (get_team_with_access, PRESET_USER, [(_ME, TEAM_ROLE_MEMBER)], {}),
    ],
)
async def test_team_gate_denies(gate, permissions, members, kwargs):
    with pytest.raises(HTTPException) as exc_info:
        await _team_gate(gate, permissions, members, **kwargs)
    assert exc_info.value.status_code == 403


@pytest.mark.asyncio
@pytest.mark.parametrize("gate, permissions", [(check_team_access, PRESET_USER), (get_team_with_access, PRESET_ADMIN)])
async def test_team_gate_raises_404_for_a_missing_team(gate, permissions):
    with pytest.raises(HTTPException) as exc_info:
        await _team_gate(gate, permissions, None)
    assert exc_info.value.status_code == 404


class TestCheckWebhookPermission:
    """check_webhook_permission: the permission plus scope access, or the scope's admin role."""

    @pytest.fixture
    def webhook_user(self):
        return User(
            id="hooker-1", username="hooker", email="h@test.com", permissions=["webhook:read", "webhook:create"]
        )

    def test_project_read_with_the_permission_needs_project_access(self, webhook_user):
        from app.api.v1.helpers.webhooks import check_webhook_permission
        from app.core.permissions import Permissions

        with patch(f"{HELPERS_WEBHOOKS}.check_project_access", new_callable=AsyncMock) as mock_access:
            asyncio.run(
                check_webhook_permission(webhook_user, MagicMock(), Permissions.WEBHOOK_READ, project_id="proj-1")
            )
        assert mock_access.call_args.args[0] == "proj-1"
        assert mock_access.call_args.kwargs == {}

    def test_project_access_without_the_permission_needs_project_admin(self, viewer_user):
        from app.api.v1.helpers.webhooks import check_webhook_permission

        with patch(f"{HELPERS_WEBHOOKS}.check_project_access", new_callable=AsyncMock) as mock_access:
            asyncio.run(check_webhook_permission(viewer_user, MagicMock(), "webhook:update", project_id="proj-1"))
        assert mock_access.call_args.kwargs["required_role"] == "admin"

    def test_team_create_with_the_permission_needs_team_membership(self, webhook_user):
        from app.api.v1.helpers.webhooks import check_webhook_permission
        from app.core.permissions import Permissions

        with patch(f"{HELPERS_WEBHOOKS}.get_team_with_access", new_callable=AsyncMock) as mock_access:
            asyncio.run(
                check_webhook_permission(webhook_user, MagicMock(), Permissions.WEBHOOK_CREATE, team_id="team-1")
            )
        assert mock_access.call_args.args[0] == "team-1"
        assert mock_access.call_args.kwargs["required_role"] == TEAM_ROLE_MEMBER

    def test_team_read_without_the_permission_needs_team_admin(self, no_perms_user):
        from app.api.v1.helpers.webhooks import check_webhook_permission
        from app.core.permissions import Permissions

        with patch(f"{HELPERS_WEBHOOKS}.check_team_access", new_callable=AsyncMock) as mock_access:
            asyncio.run(
                check_webhook_permission(no_perms_user, MagicMock(), Permissions.WEBHOOK_READ, team_id="team-1")
            )
        assert mock_access.call_args.args[0] == "team-1"
        assert mock_access.call_args.kwargs["required_role"] == TEAM_ROLE_ADMIN

    def test_global_webhook_requires_system_manage(self, regular_user):
        from app.api.v1.helpers.webhooks import check_webhook_permission

        with pytest.raises(HTTPException) as exc_info:
            asyncio.run(check_webhook_permission(regular_user, MagicMock(), "webhook:read"))
        assert exc_info.value.status_code == 403

    def test_global_webhook_admin_allowed(self, admin_user):
        from app.api.v1.helpers.webhooks import check_webhook_permission

        asyncio.run(check_webhook_permission(admin_user, MagicMock(), "webhook:read"))


class TestGetWebhookOr404:
    def test_returns_webhook_when_found(self):
        from app.api.v1.helpers.webhooks import get_webhook_or_404

        webhook = Webhook(
            id="wh-1",
            url="https://example.com",
            events=["scan_completed"],
        )
        mock_repo = MagicMock()
        mock_repo.get_by_id = AsyncMock(return_value=webhook)

        result = asyncio.run(get_webhook_or_404(mock_repo, "wh-1"))
        assert result.id == "wh-1"

    def test_raises_404_when_not_found(self):
        from app.api.v1.helpers.webhooks import get_webhook_or_404

        mock_repo = MagicMock()
        mock_repo.get_by_id = AsyncMock(return_value=None)

        with pytest.raises(HTTPException) as exc_info:
            asyncio.run(get_webhook_or_404(mock_repo, "missing"))
        assert exc_info.value.status_code == 404
