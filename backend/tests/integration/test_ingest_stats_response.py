"""The findings-ingest response body is machine-facing, so its shape is pinned."""

import threading

import pytest

from app.api.v1.helpers import ingest as ingest_helpers
from app.models.waiver import Waiver
from app.services import scan_manager

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
async def test_a_reference_given_as_one_string_is_counted_not_a_server_error(client, db, api_key_headers):
    payload = _payload()
    payload["findings"][0]["extra"]["metadata"] = {"references": "https://owasp.org/Top10/A03_2021-Injection/"}

    resp = await client.post("/api/v1/ingest/opengrep", json=payload, headers=api_key_headers)

    assert resp.status_code == 200, resp.text
    assert resp.json()["findings_count"] == len(_SEVERITIES)


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_a_skipped_entry_is_not_counted_as_a_finding(client, db, api_key_headers):
    payload = _payload()
    payload["findings"][0]["extra"]["metadata"] = {"impact": ["HIGH"]}

    resp = await client.post("/api/v1/ingest/opengrep", json=payload, headers=api_key_headers)

    assert resp.status_code == 200, resp.text
    assert (resp.json()["findings_count"], resp.json()["stats"]["total"]) == (len(_SEVERITIES) - 1,) * 2


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_ingest_writes_no_findings_to_mongo_from_this_path(client, db, api_key_headers):
    resp = await client.post("/api/v1/ingest/opengrep", json=_payload(), headers=api_key_headers)
    assert resp.status_code == 200
    assert await db.findings.count_documents({}) == 0


def _recording(original, threads: list[threading.Thread]):
    def call(*args, **kwargs):
        threads.append(threading.current_thread())
        return original(*args, **kwargs)

    return call


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_aggregation_waiver_matching_and_stats_run_off_the_event_loop(client, db, api_key_headers, monkeypatch):
    waiver = Waiver(project_id="test-project-id", package_name="src/file0.py", reason="accepted", created_by="u")
    await db.waivers.insert_one(waiver.model_dump(by_alias=True))
    threads: list[threading.Thread] = []
    for owner, name in (
        (ingest_helpers.ResultAggregator, "aggregate"),
        (scan_manager, "record_matches"),
        (ingest_helpers, "compute_stats"),
    ):
        monkeypatch.setattr(owner, name, _recording(getattr(owner, name), threads))

    resp = await client.post("/api/v1/ingest/opengrep", json=_payload(), headers=api_key_headers)

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert (body["findings_count"], body["waived_count"], body["stats"]["total"]) == (5, 1, 5)
    assert threads
    assert threading.main_thread() not in threads
