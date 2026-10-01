"""The detector name TruffleHog sends survives ingest and names the finding."""

import pytest

from app.repositories.analysis_results import RESULT_PROJECTION, AnalysisResultRepository
from app.services.aggregation import ResultAggregator
from app.services.analysis.engine import _aggregate_external_results

_INGEST_URL = "/api/v1/ingest/trufflehog"


def _payload(detector_name: str) -> dict:
    return {
        "pipeline_id": 525252,
        "commit_hash": "d" * 40,
        "branch": "main",
        "findings": [
            {
                "SourceMetadata": {"Data": {"Filesystem": {"file": "/scan/config.py", "line": 3}}},
                "SourceID": 1,
                "SourceType": 15,
                "SourceName": "trufflehog - filesystem",
                "DetectorType": 2,
                "DetectorName": detector_name,
                "DecoderName": "PLAIN",
                "Verified": False,
                "Raw": "AKIAIOSFODNN7EXAMPLE",
                "Redacted": "AKIAIOSFODNN7EXAMPLE",
            }
        ],
    }


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_the_ingested_detector_name_is_stored_and_named(client, db, api_key_headers):
    resp = await client.post(_INGEST_URL, json=_payload("AWS"), headers=api_key_headers)
    assert resp.status_code == 200, resp.text
    scan_id = resp.json()["scan_id"]
    repo = AnalysisResultRepository(db)

    row = await db.analysis_results.find_one({"scan_id": scan_id, "analyzer_name": "trufflehog"}, RESULT_PROJECTION)
    assert (await repo.load_result(row))["findings"][0]["DetectorName"] == "AWS"

    aggregator = ResultAggregator()
    await _aggregate_external_results(aggregator, repo, scan_id, [])
    (finding,) = aggregator.get_findings()
    assert (
        finding.description,
        finding.details["detector"],
        finding.details["detector_name"],
        finding.details["line"],
    ) == (
        "Secret detected: AWS",
        "2",
        "AWS",
        3,
    )


@pytest.mark.asyncio
async def test_an_oversized_detector_name_is_rejected(client, api_key_headers):
    resp = await client.post(_INGEST_URL, json=_payload("A" * 129), headers=api_key_headers)
    assert resp.status_code == 422, resp.text
