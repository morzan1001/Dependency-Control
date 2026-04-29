"""
Integration test: MAX_CRYPTO_ASSETS_PER_SCAN truncates oversized CBOM payloads.

The cbom_ingest background task truncates the asset list before persisting if
`len(assets) > MAX_CRYPTO_ASSETS_PER_SCAN`.  This test monkeypatches the limit
to 10, submits 25 components, and verifies that exactly 10 assets are persisted.

Test environment notes:
- The background task runs in-process (FastAPI's BackgroundTasks executes
  synchronously within the same event loop during tests via httpx ASGITransport).
- The task calls `worker_manager.add_job(scan_id)` at the end, which queues a
  job for the analysis worker.  No live worker is running, so the scan stays in
  "pending" status — we assert asset count only, NOT scan status.
- The `_FakeDb` in-process DB supports `count_documents`, so we can verify the
  asset count without a real MongoDB connection.
"""

import asyncio

import pytest


@pytest.mark.asyncio
async def test_oversized_cbom_is_truncated(client, db, api_key_headers, monkeypatch):
    """More than MAX_CRYPTO_ASSETS_PER_SCAN assets in payload → only that many persisted.

    Submitting 25 components with the limit patched to 10 should result in exactly
    10 CryptoAsset documents in the fake DB (the first 10 from the payload list).
    """
    import app.api.v1.endpoints.cbom_ingest as cbom_ingest

    monkeypatch.setattr(cbom_ingest, "MAX_CRYPTO_ASSETS_PER_SCAN", 10)

    components = [
        {
            "type": "cryptographic-asset",
            "bom-ref": f"c-{i}",
            "name": f"algo-{i}",
            "cryptoProperties": {
                "assetType": "algorithm",
                "algorithmProperties": {"primitive": "hash"},
            },
        }
        for i in range(25)
    ]
    payload = {
        "scan_metadata": {},
        "cbom": {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "components": components,
        },
    }

    resp = await client.post("/api/v1/ingest/cbom", json=payload, headers=api_key_headers)
    assert resp.status_code == 202, f"Expected 202 Accepted, got {resp.status_code}: {resp.text}"
    scan_id = resp.json()["scan_id"]

    # Wait briefly for the background task to run and persist assets.
    # The background task runs in-process but is scheduled asynchronously, so
    # we poll for up to 5 seconds.
    for _ in range(50):
        count = await db.crypto_assets.count_documents({"scan_id": scan_id})
        if count > 0:
            break
        await asyncio.sleep(0.1)

    crypto_count = await db.crypto_assets.count_documents({"scan_id": scan_id})
    assert crypto_count == 10, (
        f"Expected 10 assets (truncated to MAX_CRYPTO_ASSETS_PER_SCAN=10), "
        f"got {crypto_count}.  The background task may not have run yet, or "
        f"truncation is not enforced at the persistence layer."
    )
