"""K11: oversized CBOM payloads are rejected with 413 and accepted payloads persist synchronously."""

import pytest


def _cbom_payload(asset_count: int) -> dict:
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
        for i in range(asset_count)
    ]
    return {
        "scan_metadata": {},
        "cbom": {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "components": components,
        },
    }


@pytest.mark.asyncio
async def test_oversized_cbom_is_rejected_with_413(client, db, api_key_headers, monkeypatch):
    from app.api.v1.endpoints import cbom_ingest

    monkeypatch.setattr(cbom_ingest, "MAX_CRYPTO_ASSETS_PER_SCAN", 10)

    resp = await client.post("/api/v1/ingest/cbom", json=_cbom_payload(25), headers=api_key_headers)

    assert resp.status_code == 413, f"an over-cap CBOM must be rejected, not silently truncated: {resp.text}"
    stored = await db.crypto_assets.count_documents({})
    assert stored == 0, "a rejected CBOM must not persist a truncated asset set"


@pytest.mark.asyncio
async def test_cbom_within_cap_is_persisted_before_the_response_returns(client, db, api_key_headers):
    resp = await client.post("/api/v1/ingest/cbom", json=_cbom_payload(5), headers=api_key_headers)

    assert resp.status_code == 202, resp.text
    body = resp.json()
    scan_id = body["scan_id"]
    # Synchronous persistence: no background task, so the assets are stored when the 202 arrives.
    stored = await db.crypto_assets.count_documents({"scan_id": scan_id})
    assert stored == 5
    assert body["assets_received"] == 5
    assert body["assets_stored"] == 5


@pytest.mark.asyncio
async def test_duplicate_bom_refs_report_the_actually_stored_count(client, db, api_key_headers):
    """Upserts keyed on bom_ref collapse in-payload duplicates; assets_stored must say so."""
    payload = _cbom_payload(3)
    payload["cbom"]["components"][1]["bom-ref"] = payload["cbom"]["components"][0]["bom-ref"]

    resp = await client.post("/api/v1/ingest/cbom", json=payload, headers=api_key_headers)

    assert resp.status_code == 202, resp.text
    body = resp.json()
    stored = await db.crypto_assets.count_documents({"scan_id": body["scan_id"]})
    assert stored == 2
    assert body["assets_stored"] == 2, "assets_stored must reflect persisted docs, not submitted ops"
