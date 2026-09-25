"""Tests for how the Mattermost and Slack providers read the chat servers' HTTP answers."""

from typing import Any

import pytest

from app.models.system import SystemSettings
from app.services.notifications import mattermost_provider, slack_provider
from app.services.notifications.mattermost_provider import MattermostProvider
from app.services.notifications.slack_provider import SlackProvider

_BASE = "https://mm.example"


class _Response:
    def __init__(self, status_code: int, payload: Any = None) -> None:
        self.status_code = status_code
        self._payload = payload
        self.text = f"status {status_code}"

    def json(self) -> Any:
        return self._payload


class _Client:
    """Answers each request from a path-to-response table and records what was posted."""

    def __init__(self, routes: dict[str, _Response]) -> None:
        self._routes = routes
        self.posted: list[tuple[str, Any]] = []

    async def __aenter__(self) -> "_Client":
        return self

    async def __aexit__(self, *_exc: object) -> None:
        return None

    async def get(self, url: str, **_kwargs: Any) -> _Response:
        return self._routes[url.removeprefix(_BASE)]

    async def post(self, url: str, json: Any = None, **_kwargs: Any) -> _Response:
        self.posted.append((url, json))
        return self._routes[url.removeprefix(_BASE)]


def _use_client(monkeypatch, module, client: _Client) -> None:
    monkeypatch.setattr(module, "InstrumentedAsyncClient", lambda *_args, **_kwargs: client)


@pytest.mark.asyncio
@pytest.mark.parametrize(("status", "expected"), [(200, "bot-1"), (401, None)])
async def test_mattermost_bot_id_comes_only_from_a_successful_lookup(status, expected):
    client = _Client({"/api/v4/users/me": _Response(status, {"id": "bot-1"})})
    assert await MattermostProvider()._get_bot_user_id(client, _BASE, {}) == expected


@pytest.mark.asyncio
@pytest.mark.parametrize(("status", "expected"), [(200, "u-1"), (404, None)])
async def test_mattermost_user_id_comes_only_from_a_successful_lookup(status, expected):
    client = _Client({"/api/v4/users/username/alice": _Response(status, {"id": "u-1"})})
    assert await MattermostProvider()._get_user_id_by_username(client, "@alice", _BASE, {}) == expected


@pytest.mark.asyncio
@pytest.mark.parametrize(("status", "expected"), [(200, "dm-1"), (201, "dm-1"), (403, None)])
async def test_mattermost_dm_channel_comes_only_from_a_successful_create(status, expected):
    client = _Client(
        {
            "/api/v4/users/me": _Response(200, {"id": "bot-1"}),
            "/api/v4/channels/direct": _Response(status, {"id": "dm-1"}),
        }
    )
    assert await MattermostProvider()._create_dm_channel(client, "u-1", _BASE, {}) == expected


@pytest.mark.asyncio
@pytest.mark.parametrize(("status", "expected"), [(201, True), (500, False)])
async def test_mattermost_send_succeeds_only_on_a_created_post(monkeypatch, status, expected):
    client = _Client({"/api/v4/posts": _Response(status)})
    _use_client(monkeypatch, mattermost_provider, client)
    settings = SystemSettings(mattermost_url=_BASE, mattermost_bot_token="tok")
    channel = "0f8fad5b-d9cb-469f-a165-70867728950e"

    assert await MattermostProvider().send(channel, "Subj", "Body", system_settings=settings) is expected
    assert [(url, payload["channel_id"]) for url, payload in client.posted] == [(f"{_BASE}/api/v4/posts", channel)]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("status", "payload", "expected"), [(200, {"ok": True}, True), (200, {"ok": False}, False), (500, {}, False)]
)
async def test_slack_send_succeeds_only_on_an_ok_answer(monkeypatch, status, payload, expected):
    client = _Client({"https://slack.com/api/chat.postMessage": _Response(status, payload)})
    _use_client(monkeypatch, slack_provider, client)

    sent = await SlackProvider().send("#alerts", "Subj", "Body", system_settings=SystemSettings(slack_bot_token="xoxb"))

    assert sent is expected
    assert [payload["channel"] for _url, payload in client.posted] == ["#alerts"]
