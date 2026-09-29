"""Raw results: one row per scan, analyzer and source, replaced on resubmission, refused with a 413 when too large."""

import asyncio
from datetime import datetime, timezone
from typing import Any

import bson
import pytest

from app.models.project import Scan
from app.repositories.analysis_results import AnalysisResultRepository
from app.services.aggregation import ResultAggregator
from app.services.analysis.engine import (
    _aggregate_external_results,
    _carry_over_external_results,
    _process_sbom,
    process_analyzer,
)
from app.services.analysis.stats import build_epss_kev_summary
from app.services.analyzers.outdated import OutdatedAnalyzer
from tests.helpers.analyzers import serve_analyzer

_RUN = {"pipeline_id": 616161, "commit_hash": "d" * 40, "branch": "main"}
_ENVELOPE = {
    **_RUN,
    "project_name": "shop",
    "commit_message": "bump deps",
    "pipeline_user": "ci-bot",
    "job_id": 9,
    "is_release": False,
}
_MONGO_DOCUMENT_LIMIT = 16 * 1024 * 1024
_OVER_THE_DOCUMENT_LIMIT = "x" * (17 * 1024 * 1024)
_BRACE = {"name": "brace-expansion", "version": "2.0.2", "purl": "pkg:npm/brace-expansion@2.0.2"}

# trufflehog v3 `--json` line
_SECRET = {
    "SourceMetadata": {"Data": {"Filesystem": {"file": "tests/fixtures/aws.env", "line": 3}}},
    "SourceID": 1,
    "SourceType": 15,
    "SourceName": "trufflehog - filesystem",
    "DetectorType": 2,
    "DecoderName": "PLAIN",
    "Verified": False,
    "Raw": "AKIAIOSFODNN7EXAMPLE",
}

# opengrep `--json` result
_OPENGREP_FINDING = {
    "check_id": "python.lang.security.audit.eval-detected",
    "path": "src/app.py",
    "start": {"line": 12, "col": 5},
    "end": {"line": 12, "col": 21},
    "extra": {"message": "Detected the use of eval()", "severity": "WARNING"},
}

# kics `--report-formats json` query
_KICS_QUERY = {
    "query_name": "Healthcheck Instruction Missing",
    "query_id": "b03a748a-542d-44f4-bb86-9199ab4fd2d5",
    "query_url": "https://docs.docker.com/engine/reference/builder/#healthcheck",
    "severity": "LOW",
    "platform": "Dockerfile",
    "category": "Insecure Configurations",
    "description": "Ensure that HEALTHCHECK is being used.",
    "files": [
        {
            "file_name": "Dockerfile",
            "similarity_id": "b4a1a8e2c7c6f4f3a2b1",
            "line": 1,
            "issue_type": "MissingAttribute",
            "search_key": "FROM={{python:3.13-slim}}",
            "expected_value": "Dockerfile should contain instruction 'HEALTHCHECK'",
            "actual_value": "Dockerfile doesn't contain instruction 'HEALTHCHECK'",
        }
    ],
}

# bearer `--format json` report, grouped by severity
_BEARER_FINDINGS = {
    "high": [
        {
            "cwe_ids": ["798"],
            "id": "python_lang_hardcoded_secret",
            "title": "Usage of hard-coded secret",
            "description": "## Description\nStore secrets outside the code.",
            "documentation_url": "https://docs.bearer.com/reference/rules/python_lang_hardcoded_secret",
            "line_number": 4,
            "full_filename": "src/settings.py",
            "filename": "src/settings.py",
            "source": {"start": 4, "end": 4, "column": {"start": 1, "end": 20}},
            "sink": {"start": 4, "end": 4, "column": {"start": 1, "end": 20}, "content": 'API_KEY = "s3cr3t"'},
            "parent_line_number": 4,
            "fingerprint": "5e3f0c1a2b_0",
            "old_fingerprint": "9a8b7c6d5e_0",
            "code_extract": 'API_KEY = "s3cr3t"',
        }
    ]
}


class _DepsDevAnswers(OutdatedAnalyzer):
    """The outdated analyzer with deps.dev answering 5.0.0 as every package's default version."""

    async def _resolve_package_infos(self, components: list[dict[str, Any]]) -> list[dict[str, Any] | None]:
        return [{"default": "5.0.0", "withdrawn": []} for _ in components]


def _sbom(root: str) -> dict[str, Any]:
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "metadata": {"component": {"name": root}},
        "components": [{"type": "library", "bom-ref": _BRACE["purl"], **_BRACE}],
    }


async def _rows(db, scan_id: str) -> list[dict[str, Any]]:
    return await db.analysis_results.find({"scan_id": scan_id}).to_list(None)


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_a_retried_scanner_job_replaces_the_result_of_the_first_attempt(client, db, api_key_headers):
    first = await client.post(
        "/api/v1/ingest/trufflehog", json={**_RUN, "findings": [_SECRET]}, headers=api_key_headers
    )
    assert first.status_code == 200, first.text
    scan_id = first.json()["scan_id"]
    [first_row] = await _rows(db, scan_id)

    retry = await client.post("/api/v1/ingest/trufflehog", json={**_RUN, "findings": []}, headers=api_key_headers)

    assert retry.status_code == 200, retry.text
    assert [(row["_id"], row["result"]) for row in await _rows(db, scan_id)] == [(first_row["_id"], {"findings": []})]


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_a_resubmission_replaces_every_row_stored_without_a_source(db):
    # the append-only writer left one row per CI attempt
    await db.analysis_results.insert_many(
        [
            {
                "_id": f"legacy-row-{attempt}",
                "scan_id": "scan-1",
                "analyzer_name": "kics",
                "result": {"queries": [_KICS_QUERY]},
                "created_at": datetime(2026, 1, attempt, tzinfo=timezone.utc),
            }
            for attempt in (1, 2)
        ]
    )

    await AnalysisResultRepository(db).save_result("scan-1", "kics", {"queries": []})

    assert [row["result"] for row in await _rows(db, "scan-1")] == [{"queries": []}]


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_concurrent_first_writes_of_one_scanner_leave_a_single_row(db):
    repo = AnalysisResultRepository(db)
    scan_ids = [f"scan-{i}" for i in range(20)]

    for scan_id in scan_ids:
        await asyncio.gather(*(repo.save_result(scan_id, "kics", {"queries": [_KICS_QUERY]}) for _ in range(2)))

    rows = await db.analysis_results.find({}, {"scan_id": 1}).to_list(None)
    assert sorted(row["scan_id"] for row in rows) == sorted(scan_ids)


@pytest.mark.asyncio
@pytest.mark.live_mongo
@pytest.mark.parametrize(
    ("scanner", "scanner_fields"),
    [
        pytest.param("trufflehog", {"findings": [_SECRET]}, id="trufflehog"),
        pytest.param("opengrep", {"findings": [_OPENGREP_FINDING]}, id="opengrep"),
        pytest.param("kics", {"kics_version": "2.1.3", "queries": [_KICS_QUERY]}, id="kics"),
        pytest.param("bearer", {"findings": _BEARER_FINDINGS}, id="bearer"),
    ],
)
async def test_the_stored_result_holds_the_scanner_payload_alone(client, db, api_key_headers, scanner, scanner_fields):
    resp = await client.post(f"/api/v1/ingest/{scanner}", json={**_ENVELOPE, **scanner_fields}, headers=api_key_headers)

    assert resp.status_code == 200, resp.text
    [row] = await _rows(db, resp.json()["scan_id"])
    assert set(row["result"]) == set(scanner_fields)


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_a_scanner_result_too_large_to_store_is_refused_with_413(client, db, api_key_headers):
    oversized = {**_OPENGREP_FINDING, "extra": {"message": _OVER_THE_DOCUMENT_LIMIT, "severity": "WARNING"}}

    resp = await client.post("/api/v1/ingest/opengrep", json={**_RUN, "findings": [oversized]}, headers=api_key_headers)

    assert resp.status_code == 413, resp.text
    assert await db.analysis_results.count_documents({}) == 0
    scan = await db.scans.find_one({})
    assert "opengrep" not in scan.get("received_results", [])


@pytest.mark.asyncio
@pytest.mark.live_mongo
@pytest.mark.parametrize(
    "pipeline_id",
    [
        pytest.param(_RUN["pipeline_id"], id="replacing-a-row"),
        pytest.param(_RUN["pipeline_id"] + 1, id="inserting-a-row"),
    ],
)
async def test_a_result_the_server_finds_just_over_the_limit_is_refused_with_413(
    client, db, api_key_headers, pipeline_id
):
    first = await client.post(
        "/api/v1/ingest/opengrep", json={**_RUN, "findings": [_OPENGREP_FINDING]}, headers=api_key_headers
    )
    [row] = await _rows(db, first.json()["scan_id"])
    padding = "x" * (_MONGO_DOCUMENT_LIMIT + 1000 - len(bson.encode(row)))
    grown = {**_OPENGREP_FINDING, "extra": {"message": "Detected the use of eval()" + padding, "severity": "WARNING"}}

    resp = await client.post(
        "/api/v1/ingest/opengrep",
        json={**_RUN, "pipeline_id": pipeline_id, "findings": [grown]},
        headers=api_key_headers,
    )

    assert resp.status_code == 413, resp.text


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_each_sbom_keeps_its_own_row_and_a_rerun_replaces_it(db, monkeypatch):
    serve_analyzer(monkeypatch, "outdated_packages", _DepsDevAnswers())

    async def analyze(index: int) -> None:
        # the two images of a multi-arch build share their root component name
        await _process_sbom(index, _sbom("storefront"), "scan-1", db, ResultAggregator(), ["outdated_packages"], None)

    await analyze(0)
    await analyze(1)
    first_ids = sorted(row["_id"] for row in await _rows(db, "scan-1"))
    await analyze(0)

    rows = await _rows(db, "scan-1")
    assert len(first_ids) == 2
    assert sorted(row["_id"] for row in rows) == first_ids
    assert all(row["result"]["outdated_dependencies"] for row in rows)


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_a_raw_result_too_large_to_store_keeps_the_analyzer_findings(db):
    component = {**_BRACE, "name": _OVER_THE_DOCUMENT_LIMIT, "purl": "pkg:npm/huge@2.0.2"}
    aggregator = ResultAggregator()

    status = await process_analyzer(
        "outdated_packages",
        _DepsDevAnswers(),
        _sbom("storefront"),
        "scan-1",
        db,
        aggregator,
        parsed_components=[component],
    )

    assert status == "outdated_packages: Success"
    assert [finding.type for finding in aggregator.get_findings()] == ["outdated"]
    assert await _rows(db, "scan-1") == []


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_a_rescan_copies_each_external_row_once_under_an_id_derived_from_the_original(db):
    long_message = {**_OPENGREP_FINDING, "extra": {"message": "x" * (9 * 1024 * 1024), "severity": "WARNING"}}
    kics = {"kics_version": "2.1.3", "queries": [_KICS_QUERY]}
    outdated = {"outdated_dependencies": [], "ahead_of_default": [], "yanked_versions": []}
    await db.analysis_results.insert_many(
        [
            {
                "_id": "row-opengrep",
                "scan_id": "scan-1",
                "analyzer_name": "opengrep",
                "result": {"findings": [long_message]},
            },
            {"_id": "row-kics", "scan_id": "scan-1", "analyzer_name": "kics", "result": kics, "source": None},
            {"_id": "row-outdated", "scan_id": "scan-1", "analyzer_name": "outdated_packages", "result": outdated},
            {"_id": "row-epss", "scan_id": "scan-1", "analyzer_name": "epss_kev", "result": build_epss_kev_summary([])},
        ]
    )
    rescan = Scan(id="scan-2", project_id="p", branch="main", is_rescan=True, original_scan_id="scan-1")

    await _carry_over_external_results("scan-2", rescan, db)
    await _carry_over_external_results("scan-2", rescan, db)

    copies = {row["_id"]: row for row in await _rows(db, "scan-2")}
    assert sorted(copies) == ["scan-2:row-kics", "scan-2:row-opengrep"]
    assert copies["scan-2:row-kics"]["result"] == kics


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_every_external_row_of_a_scan_is_aggregated(db):
    await db.analysis_results.insert_many(
        [
            {"_id": f"row-{i}", "scan_id": "scan-1", "analyzer_name": "trufflehog", "result": {"findings": []}}
            for i in range(10_001)
        ]
    )
    summary: list[str] = []

    await _aggregate_external_results(ResultAggregator(), AnalysisResultRepository(db), "scan-1", summary)

    assert len(summary) == 10_001
