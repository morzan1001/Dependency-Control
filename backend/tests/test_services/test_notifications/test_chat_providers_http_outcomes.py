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
@pytest.mark.parametrize(("status", "expected"), [(200, "u-1"), (404, None)])
async def test_mattermost_user_id_comes_only_from_a_successful_lookup(status, expected):
    client = _Client({"/api/v4/users/username/alice": _Response(status, {"id": "u-1"})})
    assert await MattermostProvider()._get_user_id(client, "username/alice", _BASE, {}) == expected


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
    client = _Client(
        {
            "/api/v4/users/username/alice": _Response(200, {"id": "u-1"}),
            "/api/v4/users/me": _Response(200, {"id": "bot-1"}),
            "/api/v4/channels/direct": _Response(201, {"id": "dm-1"}),
            "/api/v4/posts": _Response(status),
        }
    )
    _use_client(monkeypatch, mattermost_provider, client)
    settings = SystemSettings(mattermost_url=_BASE, mattermost_bot_token="tok")

    assert await MattermostProvider().send("alice", "Subj", "Body", system_settings=settings) is expected
    url, payload = client.posted[-1]
    assert (url, payload["channel_id"]) == (f"{_BASE}/api/v4/posts", "dm-1")


@pytest.mark.asyncio
async def test_a_mattermost_dm_opens_the_channel_as_the_bot_of_the_current_token(monkeypatch):
    provider = MattermostProvider()
    for token, bot_id in [("old-tok", "bot-old"), ("new-tok", "bot-new")]:
        client = _Client(
            {
                "/api/v4/users/username/alice": _Response(200, {"id": "u-1"}),
                "/api/v4/users/me": _Response(200, {"id": bot_id}),
                "/api/v4/channels/direct": _Response(201, {"id": "dm-1"}),
                "/api/v4/posts": _Response(201),
            }
        )
        _use_client(monkeypatch, mattermost_provider, client)
        settings = SystemSettings(mattermost_url=_BASE, mattermost_bot_token=token)

        assert await provider.send("alice", "Subj", "Body", system_settings=settings) is True

    assert client.posted[0] == (f"{_BASE}/api/v4/channels/direct", ["bot-new", "u-1"])


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


@pytest.mark.asyncio
async def test_the_slack_fallback_text_keeps_a_version_range_out_of_slacks_control_syntax(monkeypatch):
    client = _Client({"https://slack.com/api/chat.postMessage": _Response(200, {"ok": True})})
    _use_client(monkeypatch, slack_provider, client)

    await SlackProvider().send(
        "#alerts", "a < b", "affected: <2.17.1 & >=2.0", system_settings=SystemSettings(slack_bot_token="xoxb")
    )

    [(_url, payload)] = client.posted
    assert payload["text"] == "*a &lt; b*\naffected: &lt;2.17.1 &amp; &gt;=2.0"
