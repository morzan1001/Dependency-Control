"""The Slack install: only a state the settings page minted may replace the system-wide bot token."""

import time
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, parse_qsl, urlsplit

import httpx
import jwt
import pytest

from app.core.config import settings
from app.core.http_utils import InstrumentedAsyncClient
from app.core.permissions import Permissions
from app.core import security
from app.core.security import create_access_token
from app.repositories.system_settings import SystemSettingsRepository
from app.services.notifications import slack_provider
from app.services.notifications.slack_provider import SlackProvider
from tests.helpers.auth import bearer_headers

_CALLBACK = f"{settings.API_V1_STR}/integrations/slack/callback"
_AUTHORIZE = f"{settings.API_V1_STR}/integrations/slack/authorize"
_OAUTH_ACCESS = "https://slack.com/api/oauth.v2.access"
_POST_MESSAGE = "https://slack.com/api/chat.postMessage"
_ADMIN = "admin"
_SLACK_APP = {"slack_client_id": "client-1", "slack_client_secret": "secret-1", "slack_bot_token": "xoxb-current"}
_SCOPES = "chat:write,im:write"
_STATE_TTL = timedelta(minutes=10)
_TOKEN_LIFETIME = 43200
_SLACK_ANSWERS = {
    _OAUTH_ACCESS: {"ok": True, "access_token": "xoxb-new", "refresh_token": "xoxe-new", "expires_in": _TOKEN_LIFETIME},
    _POST_MESSAGE: {"ok": True},
}
_OK = 200
_REDIRECT = 307
_BAD_REQUEST = 400
_FORBIDDEN = 403


@pytest.fixture
def slack(monkeypatch) -> list[dict[str, str]]:
    """Every request that reached Slack: its URL, Authorization header and form fields."""
    received: list[dict[str, str]] = []

    def answer(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        form = dict(parse_qsl(request.content.decode())) if url == _OAUTH_ACCESS else {}
        received.append({"url": url, "authorization": request.headers.get("authorization", ""), **form})
        return httpx.Response(_OK, json=_SLACK_ANSWERS[url])

    async def start(self: InstrumentedAsyncClient) -> None:
        self._client = httpx.AsyncClient(transport=httpx.MockTransport(answer))

    monkeypatch.setattr(InstrumentedAsyncClient, "start", start)
    return received


def _state(kind: str) -> dict[str, str]:
    forged = {
        "forged": "not-a-token",
        "session token": create_access_token(_ADMIN, [Permissions.SYSTEM_MANAGE]),
        "expired": security._create_token(
            subject=_ADMIN, token_type="slack_oauth", expire=datetime.now(timezone.utc) - timedelta(seconds=1)
        ),
    }
    return {"state": forged[kind]} if kind in forged else {}


async def _install_url(client) -> tuple[str, dict[str, str]]:
    authorize = await client.get(_AUTHORIZE, headers=bearer_headers(_ADMIN, [Permissions.SYSTEM_MANAGE]))
    assert authorize.status_code == _OK, authorize.text
    url = urlsplit(authorize.json()["url"])
    return url.netloc, {key: values[0] for key, values in parse_qs(url.query).items()}


@pytest.mark.live_mongo
@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["missing", "forged", "session token", "expired"])
async def test_a_callback_without_a_minted_state_keeps_the_bot_token(client, db, slack, kind):
    await SystemSettingsRepository(db).update(_SLACK_APP)

    response = await client.get(_CALLBACK, params={"code": "foreign-code", **_state(kind)})

    assert response.status_code == _BAD_REQUEST
    assert (await SystemSettingsRepository(db).get()).slack_bot_token == "xoxb-current"
    assert slack == []


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_the_settings_page_install_replaces_the_bot_token(client, db, slack):
    await SystemSettingsRepository(db).update({**_SLACK_APP, "slack_oauth_scopes": _SCOPES})

    netloc, query = await _install_url(client)
    before = time.time()
    callback = await client.get(_CALLBACK, params={"code": "admin-code", "state": query["state"]})

    assert (netloc, query["client_id"], query["scope"]) == ("slack.com", "client-1", _SCOPES)
    assert query["redirect_uri"] == f"{settings.FRONTEND_BASE_URL}{_CALLBACK}"
    assert callback.status_code == _REDIRECT
    assert callback.headers["location"] == f"{settings.FRONTEND_BASE_URL}/settings?slack_connected=true"
    [exchange] = slack
    assert (exchange["code"], exchange["redirect_uri"]) == ("admin-code", query["redirect_uri"])
    stored = await SystemSettingsRepository(db).get()
    assert (stored.slack_bot_token, stored.slack_refresh_token) == ("xoxb-new", "xoxe-new")
    assert before + _TOKEN_LIFETIME <= stored.slack_token_expires_at <= time.time() + _TOKEN_LIFETIME


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_the_install_state_expires_ten_minutes_after_it_is_minted(client, db):
    await SystemSettingsRepository(db).update(_SLACK_APP)

    minted = datetime.now(timezone.utc)
    _, query = await _install_url(client)

    expires = datetime.fromtimestamp(
        jwt.decode(query["state"], options={"verify_signature": False})["exp"], timezone.utc
    )
    # The JWT exp claim is truncated to whole seconds.
    assert minted + _STATE_TTL - timedelta(seconds=1) <= expires <= datetime.now(timezone.utc) + _STATE_TTL


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_only_a_system_manager_gets_an_install_url(client, db):
    await SystemSettingsRepository(db).update(_SLACK_APP)

    response = await client.get(_AUTHORIZE, headers=bearer_headers("bob", [Permissions.PROJECT_READ]))

    assert response.status_code == _FORBIDDEN


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_an_expiring_token_is_refreshed_persisted_and_used(db, slack, monkeypatch):
    rotating = {**_SLACK_APP, "slack_refresh_token": "xoxe-current", "slack_token_expires_at": time.time()}
    system_settings = await SystemSettingsRepository(db).update(rotating)

    async def _get_database():
        return db

    monkeypatch.setattr(slack_provider, "get_database", _get_database)
    before = time.time()

    assert await SlackProvider().send("#alerts", "Subject", "Body", system_settings=system_settings)

    refresh, post = slack
    assert (refresh["grant_type"], refresh["refresh_token"]) == ("refresh_token", "xoxe-current")
    assert (post["url"], post["authorization"]) == (_POST_MESSAGE, "Bearer xoxb-new")
    stored = await SystemSettingsRepository(db).get()
    assert (stored.slack_bot_token, stored.slack_refresh_token) == ("xoxb-new", "xoxe-new")
    assert before + _TOKEN_LIFETIME <= stored.slack_token_expires_at <= time.time() + _TOKEN_LIFETIME


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_an_install_without_rotation_drops_the_rotation_fields_of_the_last_one(client, db, slack, monkeypatch):
    rotating = {**_SLACK_APP, "slack_refresh_token": "xoxe-old", "slack_token_expires_at": time.time() - 60}
    await SystemSettingsRepository(db).update(rotating)
    monkeypatch.setitem(_SLACK_ANSWERS, _OAUTH_ACCESS, {"ok": True, "access_token": "xoxb-static"})

    async def _get_database():
        return db

    monkeypatch.setattr(slack_provider, "get_database", _get_database)
    _, query = await _install_url(client)
    await client.get(_CALLBACK, params={"code": "admin-code", "state": query["state"]})
    stored = await SystemSettingsRepository(db).get()

    assert await SlackProvider().send("#alerts", "Subject", "Body", system_settings=stored)

    assert (stored.slack_bot_token, stored.slack_refresh_token, stored.slack_token_expires_at) == (
        "xoxb-static",
        None,
        None,
    )
    assert [request["url"] for request in slack] == [_OAUTH_ACCESS, _POST_MESSAGE]
