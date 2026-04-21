"""Integration test: CBOM ingest fires a crypto_asset.ingested webhook event.

The integration fake DB does not support real webhook delivery (no webhooks
are registered, and _FakeCollection does not support the aggregation pipeline
used by WebhookDeliveriesRepository).  Instead, we monkeypatch
``webhook_service.trigger_webhooks`` with a coroutine spy so we can assert the
correct event name and payload fields were passed — without making any real
HTTP calls.
"""

import asyncio
import json
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

FIXTURES = Path(__file__).parent.parent / "fixtures" / "cbom"


@pytest.mark.asyncio
async def test_crypto_asset_ingested_dispatches_webhook(
    client, db, api_key_headers
):
    """CBOM ingest fires a crypto_asset.ingested event with summary payload."""
    dispatched_calls: list = []

    def _capture_trigger(inner_db, event_type, payload, project_id=None):
        dispatched_calls.append(
            {"event": event_type, "payload": payload, "project_id": project_id}
        )

    cbom_data = json.loads((FIXTURES / "legacy_crypto_mixed.json").read_text())
    request_payload = {
        "scan_metadata": {},
        "cbom": cbom_data,
    }

    # Patch must remain active for the duration of the background task, so we
    # start it before the request and stop it after the background task drains.
    with patch(
        "app.api.v1.endpoints.cbom_ingest.webhook_service.trigger_webhooks",
        side_effect=_capture_trigger,
    ):
        resp = await client.post(
            "/api/v1/ingest/cbom", json=request_payload, headers=api_key_headers
        )
        assert resp.status_code == 202, resp.text
        scan_id = resp.json()["scan_id"]

        # Wait for background task to complete
        for _ in range(100):
            if dispatched_calls:
                break
            await asyncio.sleep(0.05)

    assert dispatched_calls, "Expected at least one trigger_webhooks call"

    crypto_call = next(
        (c for c in dispatched_calls if c["event"] == "crypto_asset.ingested"),
        None,
    )
    assert crypto_call is not None, (
        f"Expected crypto_asset.ingested event; got: {[c['event'] for c in dispatched_calls]}"
    )

    wp = crypto_call["payload"]
    assert wp["scan_id"] == scan_id
    assert wp["total"] == 3  # legacy_crypto_mixed.json has 3 assets
    assert "by_type" in wp
