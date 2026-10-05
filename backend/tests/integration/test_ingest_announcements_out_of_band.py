"""SBOM and CBOM ingest answer the CI client before their webhook and notification are delivered."""

import asyncio
import contextlib
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from app.services.notifications.service import notification_service
from app.services.webhooks import webhook_service

_FIXTURES = Path(__file__).parents[1] / "fixtures"
_PIPELINE = {"pipeline_id": 4711, "commit_hash": "a" * 40, "branch": "main"}
_SBOM = json.loads((_FIXTURES / "sbom" / "mono.syft.json").read_text())
_CBOM = json.loads((_FIXTURES / "cbom" / "legacy_crypto_mixed.json").read_text())
_TIMEOUT_S = 10


class _RawResponse:
    def __init__(self) -> None:
        self.status: int | None = None
        self.sent = asyncio.Event()


async def _post(path: str, payload: dict, headers: dict[str, str], response: _RawResponse) -> None:
    """Drive the app over raw ASGI, because httpx's ASGITransport only returns once background tasks finish."""
    from app.main import app

    body = json.dumps(payload).encode()
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": path,
        "raw_path": path.encode(),
        "root_path": "",
        "query_string": b"",
        "headers": [
            (b"host", b"test"),
            (b"content-type", b"application/json"),
            *((name.lower().encode(), value.encode()) for name, value in headers.items()),
        ],
        "server": ("test", 80),
        "client": ("127.0.0.1", 50000),
    }
    request_sent = False

    async def receive() -> dict:
        nonlocal request_sent
        if request_sent:
            await asyncio.Event().wait()
        request_sent = True
        return {"type": "http.request", "body": body, "more_body": False}

    async def send(message: dict) -> None:
        if message["type"] == "http.response.start":
            response.status = message["status"]
        elif message["type"] == "http.response.body" and not message.get("more_body", False):
            response.sent.set()

    await app(scope, receive, send)


@pytest.mark.asyncio
@pytest.mark.live_mongo
@pytest.mark.usefixtures("client")
@pytest.mark.parametrize(
    ("path", "payload", "announcements"),
    [
        ("/api/v1/ingest", {**_PIPELINE, "sboms": [_SBOM]}, ["sbom.ingested", "sbom_ingested"]),
        ("/api/v1/ingest/cbom", {**_PIPELINE, "cbom": _CBOM}, ["crypto_asset.ingested", "crypto_asset_ingested"]),
    ],
)
async def test_ingest_responds_while_its_webhook_and_notification_hang(path, payload, announcements, api_key_headers):
    release = asyncio.Event()
    announced: list[str] = []

    async def hanging_webhook(db, event_type, payload, project_id=None, *, team_ids=None):
        announced.append(event_type)
        await release.wait()

    async def hanging_notification(project, event_type, *args, **kwargs):
        announced.append(event_type)
        await release.wait()

    response = _RawResponse()
    with (
        patch.object(webhook_service, "trigger_webhooks", hanging_webhook),
        patch.object(notification_service, "notify_project_members", hanging_notification),
    ):
        request = asyncio.create_task(_post(path, payload, api_key_headers, response))
        try:
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(response.sent.wait(), _TIMEOUT_S)
            assert response.sent.is_set(), f"the ingest response waited for the hanging delivery of {announced}"
            assert response.status == 202
        finally:
            release.set()
            await asyncio.wait_for(request, _TIMEOUT_S)

    assert announced == announcements
