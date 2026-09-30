"""SBOM ingest fires an sbom.ingested webhook; trigger_webhooks is spied to assert event name and payload shape."""

import json
from pathlib import Path
from unittest.mock import patch

import pytest

_SBOM = json.loads((Path(__file__).parents[1] / "fixtures" / "sbom" / "mono.syft.json").read_text())


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_sbom_ingested_dispatches_webhook(client, db, api_key_headers):
    dispatched_calls: list = []

    def _capture_trigger(inner_db, event_type, payload, project_id=None, team_ids=None):
        dispatched_calls.append({"event": event_type, "payload": payload, "project_id": project_id})

    request_payload = {
        "pipeline_id": 123456,
        "commit_hash": "a" * 40,
        "branch": "main",
        "pipeline_iid": 1,
        "project_url": "https://example.invalid/p",
        "sboms": [_SBOM],
    }

    with patch("app.api.v1.endpoints.ingest.webhook_service.trigger_webhooks", side_effect=_capture_trigger):
        resp = await client.post("/api/v1/ingest", json=request_payload, headers=api_key_headers)
    assert resp.status_code == 202, resp.text
    scan_id = resp.json()["scan_id"]

    sbom_call = next((c for c in dispatched_calls if c["event"] == "sbom.ingested"), None)
    assert sbom_call is not None, f"Expected sbom.ingested event; got: {[c['event'] for c in dispatched_calls]}"
    assert sbom_call["payload"] == {
        "scan_id": scan_id,
        "project_id": "test-project-id",
        "pipeline_id": 123456,
        "commit_hash": "a" * 40,
        "branch": "main",
        "sboms_processed": 1,
        "sboms_failed": 0,
    }
