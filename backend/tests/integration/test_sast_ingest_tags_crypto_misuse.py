"""SAST findings with crypto-misuse-* rule IDs are tagged CRYPTO_KEY_MANAGEMENT; other SAST rules keep the SAST type."""

import json
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent.parent / "fixtures" / "sast"
_POLL_ATTEMPTS = 100
_POLL_INTERVAL_SECONDS = 0.1
_NON_TERMINAL_STATUSES = ("running", "pending", "processing", None)


def _load_fixture(name: str) -> dict:
    with open(FIXTURES / name) as f:
        return json.load(f)


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_sast_ingest_tags_crypto_misuse_findings(client, db, running_worker, api_key_headers):
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
    assert resp.status_code == 200, resp.text
    scan_id = resp.json()["scan_id"]

    import asyncio

    # OpenGrep ingest registers its result with trigger_analysis=False by design, so nothing
    # aggregates the raw result into findings until a job is queued.
    await running_worker.add_job(scan_id)

    for _ in range(_POLL_ATTEMPTS):
        scan = await db.scans.find_one({"_id": scan_id})
        if scan and scan.get("status") not in _NON_TERMINAL_STATUSES:
            break
        await asyncio.sleep(_POLL_INTERVAL_SECONDS)

    findings = [f async for f in db.findings.find({"scan_id": scan_id})]
    km_findings = [f for f in findings if f.get("type") == "crypto_key_management"]
    sast_findings = [f for f in findings if f.get("type") == "sast"]
    assert len(km_findings) == 2
    assert len(sast_findings) == 1
    km_rule_ids = {f.get("details", {}).get("rule_id") for f in km_findings}
    assert "crypto-misuse-hardcoded-keys-python-cryptography" in km_rule_ids
    assert "crypto-misuse-ecb-mode-python" in km_rule_ids
