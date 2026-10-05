"""SSO finishes only in its starting browser, hands over the session cookie once and fails with a fixed code."""

import functools
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

import httpx
import jwt
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from app.core.config import settings
from app.core.http_utils import InstrumentedAsyncClient

_API = settings.API_V1_STR
_OK = 200
_BAD_REQUEST = 400
_CALLBACK_PAGE = f"{settings.FRONTEND_BASE_URL}/login/callback"
_TOKEN_URL = "https://gitlab.example.com/oauth/token"
_USERINFO_URL = "https://gitlab.example.com/oauth/userinfo"
_OIDC_SETTINGS = {
    "_id": "current",
    "oidc_enabled": True,
    "oidc_client_id": "dc-client",
    "oidc_client_secret": "dc-secret",
    "oidc_authorization_endpoint": "https://gitlab.example.com/oauth/authorize",
    "oidc_token_endpoint": _TOKEN_URL,
    "oidc_userinfo_endpoint": _USERINFO_URL,
}
# GitLab's answers to the token and userinfo requests.
_GITLAB_TOKENS = {
    "access_token": "gl-access",
    "token_type": "Bearer",
    "expires_in": 7200,
    "refresh_token": "gl-refresh",
    "scope": "openid profile email",
    "created_at": 1759200000,
    "id_token": "eyJhbGciOiJSUzI1NiJ9.e30.sig",
}
_GITLAB_USERINFO = {
    "sub": "4711",
    "name": "Carol Example",
    "nickname": "carol",
    "preferred_username": "carol",
    "email": "carol@example.com",
    "email_verified": True,
    "profile": "https://gitlab.example.com/carol",
    "groups": ["platform"],
}


class _GitLab:
    """The IdP's token and userinfo endpoints, recording what DC sent them."""

    def __init__(self):
        self.tokens = httpx.Response(_OK, json=_GITLAB_TOKENS)
        self.token_forms: list[dict[str, list[str]]] = []
        self.userinfo_calls = 0

    def __call__(self, request: httpx.Request) -> httpx.Response:
        if str(request.url) == _TOKEN_URL:
            self.token_forms.append(parse_qs(request.content.decode()))
            return self.tokens
        self.userinfo_calls += 1
        return httpx.Response(_OK, json=_GITLAB_USERINFO)


@pytest.fixture
def gitlab():
    idp = _GitLab()
    client = functools.partial(InstrumentedAsyncClient, transport=httpx.MockTransport(idp))
    with patch("app.api.v1.endpoints.auth.InstrumentedAsyncClient", client):
        yield idp


@pytest_asyncio.fixture
async def browser(db, fake_cache, gitlab):
    from app.api.deps import get_database
    from app.main import app

    async def _get_database():
        return db

    await db.system_settings.insert_one(dict(_OIDC_SETTINGS))
    app.dependency_overrides[get_database] = _get_database
    try:
        with patch("app.api.v1.endpoints.auth.cache_service", fake_cache):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="https://test") as client:
                yield client
    finally:
        app.dependency_overrides.pop(get_database, None)


def _new_browser() -> AsyncClient:
    from app.main import app

    return AsyncClient(transport=ASGITransport(app=app), base_url="https://test")


async def _authorize(browser: AsyncClient) -> dict[str, str]:
    response = await browser.get(f"{_API}/login/oidc/authorize")
    return {key: values[0] for key, values in parse_qs(urlsplit(response.headers["location"]).query).items()}


async def _callback(browser: AsyncClient, **params: str) -> str:
    response = await browser.get(f"{_API}/login/oidc/callback", params=params)
    return response.headers["location"]


@pytest.mark.asyncio
async def test_the_browser_that_started_sso_collects_its_session_once(browser, gitlab, db):
    authorize = await _authorize(browser)

    landing = await _callback(browser, code="gl-code", state=authorize["state"])
    first = await browser.post(f"{_API}/login/oidc/exchange")
    second = await browser.post(f"{_API}/login/oidc/exchange")

    assert landing == _CALLBACK_PAGE
    assert first.status_code == _OK
    carol = await db.users.find_one({"email": "carol@example.com"})
    claims = jwt.decode(first.json()["access_token"], settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
    assert claims["sub"] == str(carol["_id"])
    assert second.status_code == _BAD_REQUEST
    assert gitlab.token_forms[0]["redirect_uri"] == [authorize["redirect_uri"]]


@pytest.mark.asyncio
async def test_a_callback_link_opened_in_another_browser_logs_nobody_in(browser, gitlab, db):
    authorize = await _authorize(browser)

    async with _new_browser() as victim:
        landing = await _callback(victim, code="gl-code", state=authorize["state"])
        exchange = await victim.post(f"{_API}/login/oidc/exchange")

    assert landing == f"{_CALLBACK_PAGE}#error=state_expired"
    assert exchange.status_code == _BAD_REQUEST
    assert gitlab.token_forms == []
    assert await db.users.find_one({"email": "carol@example.com"}) is None


@pytest.mark.asyncio
async def test_a_consent_the_user_cancelled_lands_on_the_login_page(browser, gitlab):
    authorize = await _authorize(browser)

    landing = await _callback(
        browser, error="access_denied", error_description="The resource owner denied", state=authorize["state"]
    )

    assert landing == f"{_CALLBACK_PAGE}#error=idp_error"
    assert gitlab.token_forms == []


@pytest.mark.asyncio
async def test_sso_creates_no_account_while_auto_provisioning_is_off(browser, db):
    await db.system_settings.update_one({"_id": "current"}, {"$set": {"oidc_auto_provision": False}})
    authorize = await _authorize(browser)

    landing = await _callback(browser, code="gl-code", state=authorize["state"])
    exchange = await browser.post(f"{_API}/login/oidc/exchange")

    assert landing == f"{_CALLBACK_PAGE}#error=not_provisioned"
    assert exchange.status_code == _BAD_REQUEST
    assert await db.users.find_one({"email": "carol@example.com"}) is None


@pytest.mark.asyncio
async def test_a_token_answer_without_an_access_token_is_reported_as_a_token_error(browser, gitlab):
    gitlab.tokens = httpx.Response(
        _OK, json={"error": "invalid_grant", "error_description": "The provided authorization grant is invalid"}
    )
    authorize = await _authorize(browser)

    landing = await _callback(browser, code="gl-code", state=authorize["state"])

    assert landing == f"{_CALLBACK_PAGE}#error=token_error"
    assert gitlab.userinfo_calls == 0


@pytest.mark.asyncio
async def test_a_provider_without_a_token_endpoint_is_reported_as_not_configured(browser, gitlab, db):
    await db.system_settings.update_one({"_id": "current"}, {"$set": {"oidc_token_endpoint": None}})
    authorize = await _authorize(browser)

    landing = await _callback(browser, code="gl-code", state=authorize["state"])

    assert landing == f"{_CALLBACK_PAGE}#error=not_configured"
    assert gitlab.token_forms == []


@pytest.mark.asyncio
async def test_sso_cookies_stay_hidden_from_scripts_and_cross_site_posts(browser):
    authorize = await browser.get(f"{_API}/login/oidc/authorize")
    state = parse_qs(urlsplit(authorize.headers["location"]).query)["state"][0]
    callback = await browser.get(f"{_API}/login/oidc/callback", params={"code": "gl-code", "state": state})

    for response, name in ((authorize, "oidc_state"), (callback, "oidc_handoff")):
        cookie = next(c for c in response.headers.get_list("set-cookie") if c.startswith(f"{name}="))
        assert {"httponly", "secure", "samesite=lax"} <= {part.strip().lower() for part in cookie.split(";")}
