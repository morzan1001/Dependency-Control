"""A failed Slack token request raises SlackOAuthError whose text is the reason the callback shows."""

import httpx
import pytest

from app.core.http_utils import InstrumentedAsyncClient
from app.services.notifications import slack_provider
from app.services.notifications.slack_provider import SlackOAuthError, request_slack_tokens


def _slack_answering(monkeypatch, handler) -> None:
    def client(service_name: str, timeout: float) -> InstrumentedAsyncClient:
        return InstrumentedAsyncClient(service_name, timeout=timeout, transport=httpx.MockTransport(handler))

    monkeypatch.setattr(slack_provider, "InstrumentedAsyncClient", client)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("response", "reason"),
    [
        (httpx.Response(502), "HTTP error from Slack: 502"),
        (httpx.Response(200, json={"ok": False, "error": "invalid_code"}), "Slack API error: invalid_code"),
    ],
)
async def test_a_refused_request_names_the_reason(monkeypatch, response, reason):
    _slack_answering(monkeypatch, lambda _request: response)

    with pytest.raises(SlackOAuthError) as raised:
        await request_slack_tokens("client", "secret", grant_type="authorization_code", code="code")

    assert str(raised.value) == reason


@pytest.mark.asyncio
async def test_a_timeout_names_the_reason(monkeypatch):
    def timeout(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("slow", request=request)

    _slack_answering(monkeypatch, timeout)

    with pytest.raises(SlackOAuthError) as raised:
        await request_slack_tokens("client", "secret", grant_type="authorization_code", code="code")

    assert str(raised.value) == "Request to Slack failed (ReadTimeout)"
