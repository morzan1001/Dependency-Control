"""The findings-ingest response body is machine-facing; pin it across the stats swap."""

import pytest

_SEVERITIES = ("CRITICAL", "ERROR", "WARNING", "INFO", "NEGLIGIBLE", "BOGUS")


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
async def test_opengrep_ingest_stats_block_shape(client, db, api_key_headers):
    resp = await client.post("/api/v1/ingest/opengrep", json=_payload(), headers=api_key_headers)
    assert resp.status_code == 200, resp.text
    body = resp.json()

    assert body["findings_count"] == len(_SEVERITIES)
    assert body["waived_count"] == 0
    # ScanStatsResponse exposes exactly these keys; anything else the stats model grows is dropped.
    assert set(body["stats"]) == {"total", "critical", "high", "medium", "low", "info"}
    # OPENGREP_SEVERITY_MAP: ERROR->HIGH, WARNING->MEDIUM, INFO->LOW; CRITICAL/NEGLIGIBLE pass through; BOGUS unmapped->UNKNOWN.
    # The old ScanManager.compute_stats has no NEGLIGIBLE bucket, so NEGLIGIBLE findings land in unknown (not exposed).
    assert body["stats"]["critical"] == 1
    assert body["stats"]["high"] == 1
    assert body["stats"]["medium"] == 1
    assert body["stats"]["low"] == 1
    assert body["stats"]["info"] == 1
    # NEGLIGIBLE and BOGUS (unknown) are not exposed; the six exposed severities sum to 5.
    assert sum(body["stats"][k] for k in ("critical", "high", "medium", "low", "info")) == 5


@pytest.mark.asyncio
async def test_ingest_writes_no_findings_to_mongo_from_this_path(client, db, api_key_headers):
    """process_findings_ingest computes stats in memory; it must not persist findings."""
    await client.post("/api/v1/ingest/opengrep", json=_payload(), headers=api_key_headers)
    assert await db.findings.count_documents({}) == 0
