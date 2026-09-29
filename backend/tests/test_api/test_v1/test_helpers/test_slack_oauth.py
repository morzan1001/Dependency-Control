"""A failed Slack code exchange raises SlackOAuthError whose text is the reason the callback shows."""

import httpx
import pytest

from app.api.v1.helpers import integrations
from app.api.v1.helpers.integrations import SlackOAuthError, exchange_slack_code_for_token
from app.core.http_utils import InstrumentedAsyncClient


def _slack_answering(monkeypatch, handler) -> None:
    def client(service_name: str, timeout: float) -> InstrumentedAsyncClient:
        return InstrumentedAsyncClient(service_name, timeout=timeout, transport=httpx.MockTransport(handler))

    monkeypatch.setattr(integrations, "InstrumentedAsyncClient", client)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("response", "reason"),
    [
        (httpx.Response(502), "HTTP error from Slack: 502"),
        (httpx.Response(200, json={"ok": False, "error": "invalid_code"}), "Slack API error: invalid_code"),
    ],
)
async def test_a_refused_exchange_names_the_reason(monkeypatch, response, reason):
    _slack_answering(monkeypatch, lambda _request: response)

    with pytest.raises(SlackOAuthError) as raised:
        await exchange_slack_code_for_token("code", "client", "secret")

    assert str(raised.value) == reason


@pytest.mark.asyncio
async def test_a_timeout_names_the_reason(monkeypatch):
    def timeout(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("slow", request=request)

    _slack_answering(monkeypatch, timeout)

    with pytest.raises(SlackOAuthError) as raised:
        await exchange_slack_code_for_token("code", "client", "secret")

    assert str(raised.value) == "Request to Slack timed out"
