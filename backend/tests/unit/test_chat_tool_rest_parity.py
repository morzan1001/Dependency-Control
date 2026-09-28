"""Chat and MCP tool results reach the browser, the chat history and an external LLM client, so a
tool may expose only what the REST response schema for the same object does, and only to a caller
REST would answer."""

import json
from datetime import datetime, timezone

import pytest

from app.core.permissions import Permissions
from app.models.user import User
from app.services.chat.tools import ChatToolRegistry
from tests.helpers.permission_presets import PRESET_ADMIN, PRESET_USER
from tests.mocks.fake_mongo import FakeDatabase

_NOW = datetime(2026, 9, 25, 12, 0, tzinfo=timezone.utc)
_CALLER = "u-caller"
_PROJECT = "p-1"
_TEAM = "t-1"
_WEBHOOK = "hook-1"
_DELIVERY_STATUS = 502
_HMAC_SECRET = "hmac-signing-secret-value"
_AUTH_HEADER = "Bearer receiver-credential-value"
_API_KEY_HASH = "$argon2id$v=19$m=65536,t=3,p=4$project-api-key-hash-value"
_SYSTEM_SECRETS = {
    "github_token": "ghp-github-token-value",
    "smtp_password": "smtp-password-value",
    "open_source_malware_api_key": "osm-api-key-value",
    "slack_bot_token": "xoxb-slack-bot-token-value",
    "slack_client_secret": "slack-client-secret-value",
    "slack_refresh_token": "slack-refresh-token-value",
    "oidc_client_secret": "oidc-client-secret-value",
    "gitlab_access_token": "glpat-gitlab-token-value",
    "mattermost_bot_token": "mattermost-bot-token-value",
}


def _user(permissions: list[str]) -> User:
    return User(id=_CALLER, username="caller", email="caller@test.com", permissions=permissions)


def _seeded(*, member_role: str | None = None, team_role: str | None = None) -> FakeDatabase:
    db = FakeDatabase()
    db.projects._docs[_PROJECT] = {
        "_id": _PROJECT,
        "name": "checkout",
        "team_ids": [_TEAM],
        "members": [{"user_id": _CALLER, "role": member_role}] if member_role else [],
        "api_key_hash": _API_KEY_HASH,
        "created_at": _NOW,
    }
    db.teams._docs[_TEAM] = {
        "_id": _TEAM,
        "name": "payments",
        "members": [{"user_id": _CALLER, "role": team_role}] if team_role else [],
    }
    db.webhooks._docs[_WEBHOOK] = {
        "_id": _WEBHOOK,
        "project_id": _PROJECT,
        "url": "https://receiver.test/hook",
        "events": ["scan_completed"],
        "secret": _HMAC_SECRET,
        "headers": {"Authorization": _AUTH_HEADER},
        "is_active": True,
        "webhook_type": "generic",
        "created_at": _NOW,
    }
    db.webhook_deliveries._docs["wd-1"] = {
        "_id": "wd-1",
        "webhook_id": _WEBHOOK,
        "status_code": _DELIVERY_STATUS,
        "timestamp": _NOW,
    }
    db.system_settings._docs["current"] = {"_id": "current", "smtp_host": "smtp.test", **_SYSTEM_SECRETS}
    return db


async def _call(tool_name: str, arguments: dict, user: User, db: FakeDatabase) -> dict:
    return await ChatToolRegistry().execute_tool(tool_name, arguments, user, db)


@pytest.mark.asyncio
async def test_listed_webhooks_carry_neither_the_signing_secret_nor_the_receiver_headers() -> None:
    result = await _call("list_project_webhooks", {"project_id": _PROJECT}, _user(PRESET_ADMIN), _seeded())

    assert [hook["id"] for hook in result["webhooks"]] == [_WEBHOOK]
    assert _HMAC_SECRET not in json.dumps(result, default=str)
    assert _AUTH_HEADER not in json.dumps(result, default=str)


@pytest.mark.asyncio
async def test_system_settings_report_that_a_secret_is_configured_not_its_value() -> None:
    result = await _call("get_system_settings", {}, _user(PRESET_ADMIN), _seeded())

    answer = json.dumps(result, default=str)
    assert result["settings"]["smtp_host"] == "smtp.test"
    assert all(result["settings"][f"{field}_configured"] is True for field in _SYSTEM_SECRETS)
    assert [value for value in _SYSTEM_SECRETS.values() if value in answer] == []


@pytest.mark.asyncio
async def test_project_details_leave_out_the_ingest_key_hash() -> None:
    result = await _call("get_project_details", {"project_id": _PROJECT}, _user(PRESET_ADMIN), _seeded())

    assert result["project"]["name"] == "checkout"
    assert _API_KEY_HASH not in json.dumps(result, default=str)


@pytest.mark.parametrize(
    ("member_role", "team_role"),
    [("viewer", None), ("editor", None), (None, "member")],
    ids=["viewer-member", "editor-member", "team-member"],
)
@pytest.mark.asyncio
async def test_a_member_below_project_admin_without_webhook_read_is_refused(
    member_role: str | None, team_role: str | None
) -> None:
    db = _seeded(member_role=member_role, team_role=team_role)
    user = _user(PRESET_USER)

    listing = await _call("list_project_webhooks", {"project_id": _PROJECT}, user, db)
    deliveries = await _call("get_webhook_deliveries", {"webhook_id": _WEBHOOK}, user, db)

    assert listing == await _call("list_project_webhooks", {"project_id": "p-absent"}, user, db)
    assert deliveries == await _call("get_webhook_deliveries", {"webhook_id": "hook-absent"}, user, db)
    assert "not found or access denied" in listing["error"]
    assert "not found or access denied" in deliveries["error"]


@pytest.mark.parametrize(
    ("permissions", "member_role", "team_role"),
    [
        (PRESET_USER, "admin", None),
        (PRESET_USER, None, "admin"),
        ([*PRESET_USER, Permissions.WEBHOOK_READ], "viewer", None),
    ],
    ids=["project-admin", "team-derived-admin", "webhook-read-viewer"],
)
@pytest.mark.asyncio
async def test_a_caller_rest_lets_read_webhooks_is_answered(
    permissions: list[str], member_role: str | None, team_role: str | None
) -> None:
    db = _seeded(member_role=member_role, team_role=team_role)
    user = _user(permissions)

    listing = await _call("list_project_webhooks", {"project_id": _PROJECT}, user, db)
    deliveries = await _call("get_webhook_deliveries", {"webhook_id": _WEBHOOK}, user, db)

    assert [hook["id"] for hook in listing["webhooks"]] == [_WEBHOOK]
    assert [row["status_code"] for row in deliveries["deliveries"]] == [_DELIVERY_STATUS]
