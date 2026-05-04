"""Integration test: SBOM ingest fires an ``sbom.ingested`` webhook event.

Mirrors test_crypto_asset_ingested_webhook for the SBOM ingest path. We
monkeypatch ``webhook_service.trigger_webhooks`` with a spy to assert the
correct event name and payload shape without making real HTTP calls.
"""

from unittest.mock import patch

import pytest


@pytest.mark.asyncio
async def test_sbom_ingested_dispatches_webhook(client, db, api_key_headers):
    """POST /api/v1/ingest fires sbom.ingested with the scan summary."""
    dispatched_calls: list = []

    def _capture_trigger(inner_db, event_type, payload, project_id=None):
        dispatched_calls.append({"event": event_type, "payload": payload, "project_id": project_id})

    request_payload = {
        "pipeline_id": 123456,
        "commit_hash": "a" * 40,
        "branch": "main",
        "pipeline_iid": 1,
        "project_url": "https://example.invalid/p",
        "sboms": [
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "version": 1,
                "components": [],
            }
        ],
    }

    async def _fake_process_sboms(*args, **kwargs):
        # (sbom_refs, warnings, sboms_processed, sboms_failed, total_deps_inserted)
        return ([{"gridfs_id": "fake-1", "filename": "fake.json"}], [], 1, 0, 0)

    with (
        patch(
            "app.api.v1.endpoints.ingest.webhook_service.trigger_webhooks",
            side_effect=_capture_trigger,
        ),
        patch(
            "app.api.v1.endpoints.ingest._process_sboms",
            side_effect=_fake_process_sboms,
        ),
        patch("app.api.v1.endpoints.ingest.AsyncIOMotorGridFSBucket"),
    ):
        resp = await client.post("/api/v1/ingest", json=request_payload, headers=api_key_headers)
        assert resp.status_code == 202, resp.text
        scan_id = resp.json()["scan_id"]

    assert dispatched_calls, "Expected at least one trigger_webhooks call"

    sbom_call = next(
        (c for c in dispatched_calls if c["event"] == "sbom.ingested"),
        None,
    )
    assert sbom_call is not None, f"Expected sbom.ingested event; got: {[c['event'] for c in dispatched_calls]}"
    wp = sbom_call["payload"]
    assert wp["scan_id"] == scan_id
    assert wp["branch"] == "main"
    assert wp["pipeline_id"] == 123456
    assert "sboms_processed" in wp
    assert "dependencies_count" in wp
