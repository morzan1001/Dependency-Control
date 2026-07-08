"""MAX_CRYPTO_ASSETS_PER_SCAN truncates oversized CBOM payloads before persisting."""

import asyncio

import pytest


@pytest.mark.asyncio
async def test_oversized_cbom_is_truncated(client, db, api_key_headers, monkeypatch):
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

    # Poll for the async background task to persist assets.
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
