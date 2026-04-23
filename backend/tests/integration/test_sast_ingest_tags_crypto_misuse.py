"""
Integration test: OpenGrep findings with crypto-misuse-* rule IDs must be
tagged as CRYPTO_KEY_MANAGEMENT; regular SAST rule IDs keep the SAST type.

The unit tests in test_sast_normalizer_crypto_misuse.py are the primary proof
of correctness for the normalizer mapping. This test exercises the full
ingest→normalize→persist path end-to-end through the mock FastAPI stack.
"""

import json
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent.parent / "fixtures" / "sast"


def _load_fixture(name: str) -> dict:
    with open(FIXTURES / name) as f:
        return json.load(f)


@pytest.mark.skip(reason="requires full ingest worker — mock DB lacks find_one_and_update; unit coverage in test_sast_normalizer_crypto_misuse.py is the primary proof")
@pytest.mark.asyncio
async def test_sast_ingest_tags_crypto_misuse_findings(client, db, api_key_headers):
    """Finding with rule_id starting with 'crypto-misuse-' must be tagged
    as CRYPTO_KEY_MANAGEMENT; regular SAST rules keep the SAST type."""
    sast_payload = _load_fixture("crypto_misuse_findings.json")

    resp = await client.post(
        "/api/v1/ingest/opengrep",
        json={
            "pipeline_id": 1,
            "commit_hash": "abc123deadbeef",
            "branch": "main",
            "findings": sast_payload["results"],
        },
        headers=api_key_headers,
    )
    assert resp.status_code == 202, resp.text
    scan_id = resp.json()["scan_id"]

    import asyncio
    for _ in range(100):
        scan = await db.scans.find_one({"_id": scan_id})
        if scan and scan.get("status") not in ("running", "pending", None):
            break
        await asyncio.sleep(0.1)

    findings = [f async for f in db.findings.find({"scan_id": scan_id})]
    km_findings = [f for f in findings if f.get("type") == "crypto_key_management"]
    sast_findings = [f for f in findings if f.get("type") == "sast"]
    assert len(km_findings) == 2
    assert len(sast_findings) == 1
    # Confirm the right rule_ids ended up in the right bucket
    km_rule_ids = {f.get("details", {}).get("rule_id") for f in km_findings}
    assert "crypto-misuse-hardcoded-keys-python-cryptography" in km_rule_ids
    assert "crypto-misuse-ecb-mode-python" in km_rule_ids
