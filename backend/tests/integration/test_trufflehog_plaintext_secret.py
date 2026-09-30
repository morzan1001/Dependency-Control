"""TruffleHog's plaintext secret reaches neither Mongo nor the results API, and the finding_id stays put."""

import hashlib
import json

import pytest

from app.repositories.analysis_results import RESULT_PROJECTION, AnalysisResultRepository
from app.services.aggregation import ResultAggregator
from app.services.analysis.engine import _aggregate_external_results

_SECRET = "AKIAIOSFODNN7EXAMPLE"
_FULL_DIGEST = hashlib.md5(_SECRET.encode()).hexdigest()
# Pinned rather than recomputed: secret waivers anchor on this exact id.
_PINNED_FINDING_ID = "SECRET-2-317e5726"
_PINNED_DIGEST_PREFIX = "317e5726"
_LEGACY_SCAN = "legacy-scan"
_TRUFFLEHOG = "trufflehog"
_INGEST_URL = "/api/v1/ingest/trufflehog"


def _payload(raw: object = _SECRET) -> dict:
    return {
        "pipeline_id": 515151,
        "commit_hash": "c" * 40,
        "branch": "main",
        "findings": [
            {
                "DetectorType": 2,
                "Raw": raw,
                "RawV2": f"{_SECRET}wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                "Verified": True,
                "SourceMetadata": {"Data": {"Filesystem": {"file": "config/aws.env"}}},
            }
        ],
    }


async def _aggregated_ids(db, scan_id: str) -> list[str]:
    aggregator = ResultAggregator()
    await _aggregate_external_results(aggregator, AnalysisResultRepository(db), scan_id, [])
    return [f.id for f in aggregator.get_findings()]


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_ingest_neither_stores_nor_serves_the_plaintext_secret(client, db, api_key_headers, member_auth_headers):
    resp = await client.post(_INGEST_URL, json=_payload(), headers=api_key_headers)
    assert resp.status_code == 200, resp.text
    scan_id = resp.json()["scan_id"]

    row = await db.analysis_results.find_one({"scan_id": scan_id, "analyzer_name": _TRUFFLEHOG}, RESULT_PROJECTION)
    stored = json.dumps(await AnalysisResultRepository(db).load_result(row))
    assert _SECRET not in stored
    assert _FULL_DIGEST not in stored
    assert json.loads(stored)["findings"][0]["RawHash"] == _PINNED_DIGEST_PREFIX

    served = await client.get(f"/api/v1/projects/scans/{scan_id}/results/{row['_id']}", headers=member_auth_headers)
    assert served.status_code == 200, served.text
    assert served.json()["findings"][0]["RawHash"] == _PINNED_DIGEST_PREFIX
    assert b'"Raw"' not in served.content
    assert _SECRET.encode() not in served.content
    assert _FULL_DIGEST.encode() not in served.content


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_ingested_secret_keeps_its_finding_id(client, db, api_key_headers):
    resp = await client.post(_INGEST_URL, json=_payload(), headers=api_key_headers)
    assert resp.status_code == 200, resp.text

    assert await _aggregated_ids(db, resp.json()["scan_id"]) == [_PINNED_FINDING_ID]


@pytest.mark.asyncio
async def test_legacy_stored_raw_keeps_its_finding_id(db):
    await db.analysis_results.insert_one(
        {
            "_id": "legacy-result",
            "scan_id": _LEGACY_SCAN,
            "analyzer_name": _TRUFFLEHOG,
            "result": {
                "findings": [
                    {
                        "DetectorType": "2",
                        "Raw": _SECRET,
                        "Verified": True,
                        "SourceMetadata": {"Data": {"Filesystem": {"file": "config/aws.env"}}},
                    }
                ]
            },
        }
    )

    assert await _aggregated_ids(db, _LEGACY_SCAN) == [_PINNED_FINDING_ID]


@pytest.mark.asyncio
async def test_a_row_migrated_to_the_digest_prefix_keeps_its_finding_id(db):
    await db.analysis_results.insert_one(
        {
            "_id": "migrated-result",
            "scan_id": _LEGACY_SCAN,
            "analyzer_name": _TRUFFLEHOG,
            "result": {"findings": [{"DetectorType": "2", "RawHash": _PINNED_DIGEST_PREFIX, "Verified": True}]},
        }
    )

    assert await _aggregated_ids(db, _LEGACY_SCAN) == [_PINNED_FINDING_ID]


@pytest.mark.asyncio
async def test_non_string_raw_is_rejected_as_invalid(client, api_key_headers):
    resp = await client.post(_INGEST_URL, json=_payload(raw=12345), headers=api_key_headers)

    assert resp.status_code == 422, resp.text
