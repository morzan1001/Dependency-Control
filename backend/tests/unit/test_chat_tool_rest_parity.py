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


_TEAM_WEBHOOK = "hook-team"
_GLOBAL_WEBHOOK = "hook-global"


def _with_team_and_global_webhooks(db: FakeDatabase) -> FakeDatabase:
    for hook_id, project_id, team_id in ((_TEAM_WEBHOOK, None, _TEAM), (_GLOBAL_WEBHOOK, None, None)):
        db.webhooks._docs[hook_id] = {
            **db.webhooks._docs[_WEBHOOK],
            "_id": hook_id,
            "project_id": project_id,
            "team_id": team_id,
        }
        db.webhook_deliveries._docs[f"wd-{hook_id}"] = {
            "_id": f"wd-{hook_id}",
            "webhook_id": hook_id,
            "status_code": _DELIVERY_STATUS,
            "timestamp": _NOW,
        }
    return db


@pytest.mark.parametrize(
    ("permissions", "team_role"),
    [([*PRESET_USER, Permissions.WEBHOOK_READ], "member"), (PRESET_USER, "admin")],
    ids=["webhook-read-team-member", "team-admin"],
)
@pytest.mark.asyncio
async def test_a_team_webhook_s_deliveries_answer_whom_rest_lets_read_the_webhook(
    permissions: list[str], team_role: str
) -> None:
    db = _with_team_and_global_webhooks(_seeded(team_role=team_role))

    deliveries = await _call("get_webhook_deliveries", {"webhook_id": _TEAM_WEBHOOK}, _user(permissions), db)

    assert [row["status_code"] for row in deliveries["deliveries"]] == [_DELIVERY_STATUS]


@pytest.mark.parametrize(
    ("permissions", "team_role", "webhook_id"),
    [
        (PRESET_USER, "member", _TEAM_WEBHOOK),
        ([*PRESET_USER, Permissions.WEBHOOK_READ], None, _TEAM_WEBHOOK),
        ([*PRESET_USER, Permissions.WEBHOOK_READ], "admin", _GLOBAL_WEBHOOK),
    ],
    ids=["team-member-without-webhook-read", "webhook-read-outside-the-team", "global-without-system-manage"],
)
@pytest.mark.asyncio
async def test_team_and_global_deliveries_are_refused_as_if_the_webhook_were_absent(
    permissions: list[str], team_role: str | None, webhook_id: str
) -> None:
    db = _with_team_and_global_webhooks(_seeded(team_role=team_role))
    user = _user(permissions)

    deliveries = await _call("get_webhook_deliveries", {"webhook_id": webhook_id}, user, db)

    assert deliveries == await _call("get_webhook_deliveries", {"webhook_id": "hook-absent"}, user, db)


@pytest.mark.asyncio
async def test_a_system_manager_reads_a_global_webhook_s_deliveries() -> None:
    db = _with_team_and_global_webhooks(_seeded())

    deliveries = await _call("get_webhook_deliveries", {"webhook_id": _GLOBAL_WEBHOOK}, _user(PRESET_ADMIN), db)

    assert [row["status_code"] for row in deliveries["deliveries"]] == [_DELIVERY_STATUS]


@pytest.mark.parametrize(
    ("permissions", "member_role", "team_role", "expected"),
    [
        ([*PRESET_USER, Permissions.WEBHOOK_READ], "viewer", "member", {_WEBHOOK: "project", _TEAM_WEBHOOK: "team"}),
        ([*PRESET_USER, Permissions.WEBHOOK_READ], "viewer", None, {_WEBHOOK: "project"}),
        (
            PRESET_ADMIN,
            None,
            None,
            {_WEBHOOK: "project", _TEAM_WEBHOOK: "team", _GLOBAL_WEBHOOK: "global"},
        ),
    ],
    ids=["team-member", "project-member-only", "system-manager"],
)
@pytest.mark.asyncio
async def test_a_project_s_webhook_list_holds_every_hook_that_fires_for_it_the_caller_may_read(
    permissions: list[str], member_role: str | None, team_role: str | None, expected: dict[str, str]
) -> None:
    db = _with_team_and_global_webhooks(_seeded(member_role=member_role, team_role=team_role))

    listing = await _call("list_project_webhooks", {"project_id": _PROJECT}, _user(permissions), db)

    assert {hook["id"]: hook["scope"] for hook in listing["webhooks"]} == expected


@pytest.mark.parametrize("tool_name", ["get_team_details", "get_team_projects", "get_team_risk_overview"])
@pytest.mark.asyncio
async def test_a_team_refusal_is_indistinguishable_from_the_team_not_existing(tool_name: str) -> None:
    db = _seeded(member_role="viewer")
    user = _user(PRESET_USER)

    denied = await _call(tool_name, {"team_id": _TEAM}, user, db)

    assert denied == await _call(tool_name, {"team_id": "t-absent"}, user, db)
    assert "not found or access denied" in denied["error"]


@pytest.mark.asyncio
async def test_a_stored_webhook_the_model_rejects_answers_as_absent_without_quoting_its_secret() -> None:
    db = _seeded()
    del db.webhooks._docs[_WEBHOOK]["events"]
    user = _user(PRESET_ADMIN)

    deliveries = await _call("get_webhook_deliveries", {"webhook_id": _WEBHOOK}, user, db)

    assert deliveries == await _call("get_webhook_deliveries", {"webhook_id": "hook-absent"}, user, db)
    assert _HMAC_SECRET not in json.dumps(deliveries, default=str)
