"""The findings-ingest response body is machine-facing; pin it across the stats swap."""

import pytest

_SEVERITIES = ("CRITICAL", "ERROR", "WARNING", "INFO", "NEGLIGIBLE", "BOGUS")
# ERROR->HIGH, WARNING->MEDIUM, INFO->LOW; an unmapped severity (BOGUS) counts as unknown.
_EXPECTED_STATS = {
    "total": 6,
    "critical": 1,
    "high": 1,
    "medium": 1,
    "low": 1,
    "negligible": 1,
    "info": 0,
    "unknown": 1,
}


def _payload():
    return {
        "pipeline_id": 424242,
        "commit_hash": "b" * 40,
        "branch": "main",
        "findings": [
            {
                "check_id": f"rules.sev-{sev.lower()}",
                "path": f"src/file{i}.py",
                "start": {"line": 1, "col": 1},
                "end": {"line": 1, "col": 9},
                "extra": {"message": f"issue {i}", "severity": sev},
            }
            for i, sev in enumerate(_SEVERITIES)
        ],
    }


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_opengrep_ingest_stats_block_shape(client, db, api_key_headers):
    resp = await client.post("/api/v1/ingest/opengrep", json=_payload(), headers=api_key_headers)
    assert resp.status_code == 200, resp.text
    body = resp.json()

    assert body["findings_count"] == len(_SEVERITIES)
    assert body["waived_count"] == 0
    assert body["stats"] == _EXPECTED_STATS


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_ingest_writes_no_findings_to_mongo_from_this_path(client, db, api_key_headers):
    """process_findings_ingest computes stats in memory; it must not persist findings."""
    resp = await client.post("/api/v1/ingest/opengrep", json=_payload(), headers=api_key_headers)
    assert resp.status_code == 200
    assert await db.findings.count_documents({}) == 0
