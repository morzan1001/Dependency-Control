"""Raw results: one GridFS file per scan, analyzer and source, replaced on resubmission, read through one loader."""

import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest
from bson import ObjectId

from app.core.constants import SCAN_STATUS_COMPLETED
from app.core.init_db import create_indexes
from app.models.project import Scan
from app.repositories.analysis_results import AnalysisResultRepository
from app.services.aggregation import ResultAggregator
from app.services.analysis.engine import (
    _aggregate_external_results,
    _carry_over_external_results,
    run_analysis,
)
from app.services.analysis.stats import build_epss_kev_summary
from app.services.analyzers.outdated import OutdatedAnalyzer
from app.services.gridfs_maintenance import reap_orphan_gridfs_files
from tests.helpers.analyzers import analyze_cyclonedx, build_analyzer, process_sbom_document, serve_analyzer
from tests.helpers.sboms import store_sbom

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
_FIXTURES = Path(__file__).parents[1] / "fixtures"
_KICS_REPORT = json.loads((_FIXTURES / "iac/kics_2.1.20_results.json").read_text())
_SYFT_COMPONENT = json.loads((_FIXTURES / "sbom/npmpeer.syft.cdx.json").read_text())["components"][0]
_SECRET = json.loads((_FIXTURES / "secrets/trufflehog_v3_line.json").read_text())
_OPENGREP_FINDING = json.loads((_FIXTURES / "sast/opengrep_result.json").read_text())
_WORKER = "pod-a/worker-0"
_BRACE = {"name": "brace-expansion", "version": "2.0.2", "purl": "pkg:npm/brace-expansion@2.0.2"}

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


async def _stored(db, row: dict[str, Any]) -> Any:
    return await AnalysisResultRepository(db).load_result(row)


async def _file_length(db, file_id: str) -> int:
    return (await db["fs.files"].find_one({"_id": ObjectId(file_id)}))["length"]


def _kics_report_of_a_monorepo(services: int) -> dict[str, Any]:
    """The real kics report as if every one of ``services`` services held the scanned files."""
    return {
        **_KICS_REPORT,
        "queries": [
            {
                **query,
                "files": [
                    {**file, "file_name": f"services/svc-{n:05d}/{file['file_name']}"}
                    for n in range(services)
                    for file in query["files"]
                ],
            }
            for query in _KICS_REPORT["queries"]
        ],
    }


async def _analyze_sbom_of_a_new_scan(db, components: list[dict[str, Any]]) -> str:
    """One scan whose SBOM is stored the way ingest stores it, analysed by the outdated analyzer."""
    ref = await store_sbom(db, {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": components})
    scan = Scan(project_id="p", branch="main", sbom_refs=[ref], status="processing", worker_id=_WORKER)
    await db.scans.insert_one(scan.model_dump(by_alias=True))
    assert await run_analysis(scan.id, [ref], ["outdated_packages"], db, worker_id=_WORKER) == SCAN_STATUS_COMPLETED
    return scan.id


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
    assert [(row["_id"], await _stored(db, row)) for row in await _rows(db, scan_id)] == [
        (first_row["_id"], {"findings": []})
    ]


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_a_resubmission_replaces_every_row_stored_without_a_source(db):
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

    assert [await _stored(db, row) for row in await _rows(db, "scan-1")] == [{"queries": []}]


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
    assert set(await _stored(db, row)) == set(scanner_fields)


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_a_run_without_a_pipeline_stores_its_result_under_its_own_scan(client, db, api_key_headers):
    resp = await client.post(
        "/api/v1/ingest/kics",
        json={**_RUN, "pipeline_id": 0, "queries": [_KICS_QUERY]},
        headers=api_key_headers,
    )

    assert resp.status_code == 200, resp.text
    [row] = await _rows(db, resp.json()["scan_id"])
    scan = await db.scans.find_one({"_id": row["scan_id"]})
    assert scan["received_results"] == ["kics"]


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_each_sbom_keeps_its_own_row_and_a_rerun_replaces_it(db, monkeypatch):
    serve_analyzer(monkeypatch, "outdated_packages", _DepsDevAnswers())

    async def analyze(index: int) -> None:
        # the two images of a multi-arch build share their root component name
        await process_sbom_document(
            index, _sbom("storefront"), "scan-1", db, ResultAggregator(), ["outdated_packages"], None
        )

    await analyze(0)
    await analyze(1)
    first_ids = sorted(row["_id"] for row in await _rows(db, "scan-1"))
    await analyze(0)

    rows = await _rows(db, "scan-1")
    assert len(first_ids) == 2
    assert sorted(row["_id"] for row in rows) == first_ids
    assert all([(await _stored(db, row))["outdated_dependencies"] for row in rows])


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_a_kics_result_over_16_mib_is_stored_and_every_finding_aggregated(client, db, api_key_headers):
    report = _kics_report_of_a_monorepo(6500)
    file_entries = sum(len(query["files"]) for query in report["queries"])

    resp = await client.post("/api/v1/ingest/kics", json={**_RUN, **report}, headers=api_key_headers)

    assert resp.status_code == 200, resp.text
    assert resp.json()["findings_count"] == file_entries
    [row] = await _rows(db, resp.json()["scan_id"])
    assert "result" not in row
    assert await _file_length(db, row["result_gridfs_id"]) > _MONGO_DOCUMENT_LIMIT
    aggregator = ResultAggregator()
    await _aggregate_external_results(aggregator, AnalysisResultRepository(db), row["scan_id"], [])
    assert len(aggregator.get_findings()) == file_entries


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_an_engine_license_result_over_16_mib_is_stored_as_a_file(db):
    components = [
        {
            **_SYFT_COMPONENT,
            "bom-ref": f"pkg:npm/js-tokens-{i}@4.0.0",
            "name": f"js-tokens-{i}",
            "purl": f"pkg:npm/js-tokens-{i}@4.0.0",
            "licenses": [{"license": {"id": "GPL-3.0-only"}}],
        }
        for i in range(12_000)
    ]
    sbom = {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": components}

    summary = await process_sbom_document(0, sbom, "scan-1", db, ResultAggregator(), ["license_compliance"], None)

    assert summary == ["license_compliance: Success"]
    [row] = await _rows(db, "scan-1")
    assert await _file_length(db, row["result_gridfs_id"]) > _MONGO_DOCUMENT_LIMIT
    assert await _stored(db, row) == await analyze_cyclonedx(build_analyzer("license_compliance"), components)


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_the_rollup_reads_the_outdated_file_and_the_predecessor_set(db, monkeypatch):
    await create_indexes(db)
    serve_analyzer(monkeypatch, "outdated_packages", _DepsDevAnswers())
    behind = {"type": "library", "bom-ref": _BRACE["purl"], **_BRACE}
    first = await _analyze_sbom_of_a_new_scan(db, [behind])
    await db.analysis_results.delete_many({"scan_id": first})

    second = await _analyze_sbom_of_a_new_scan(
        db, [{**behind, "version": "5.0.0", "purl": "pkg:npm/brace-expansion@5.0.0"}]
    )

    delta = await db.scan_update_deltas.find_one({"_id": second})
    assert (delta["prev_scan_id"], delta["outdated_count"], delta["outdated_resolved"]) == (
        first,
        0,
        ["brace-expansion"],
    )


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_a_legacy_inline_row_is_aggregated_and_listed(db):
    await db.analysis_results.insert_one(
        {
            "_id": "0b6f2a4e-3c1d-4f5a-9e8b-7d6c5b4a3f21",
            "scan_id": "scan-1",
            "analyzer_name": "kics",
            "result": {"kics_version": "2.1.3", "queries": [_KICS_QUERY]},
            "created_at": datetime(2026, 1, 1, tzinfo=timezone.utc),
        }
    )
    aggregator = ResultAggregator()

    await _aggregate_external_results(aggregator, AnalysisResultRepository(db), "scan-1", [])

    assert [finding.type for finding in aggregator.get_findings()] == ["iac"]
    [listed] = await AnalysisResultRepository(db).find_by_scan("scan-1", limit=10)
    assert (listed.id, listed.analyzer_name, listed.source) == ("0b6f2a4e-3c1d-4f5a-9e8b-7d6c5b4a3f21", "kics", None)


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_results_endpoint_returns_metadata_for_file_and_inline_rows(
    client, db, api_key_headers, member_auth_headers
):
    resp = await client.post("/api/v1/ingest/kics", json={**_RUN, "queries": [_KICS_QUERY]}, headers=api_key_headers)
    scan_id = resp.json()["scan_id"]
    await db.analysis_results.insert_one(
        {
            "_id": "legacy-row",
            "scan_id": scan_id,
            "analyzer_name": "trufflehog",
            "result": {"findings": [_SECRET]},
            "created_at": datetime(2026, 1, 1, tzinfo=timezone.utc),
        }
    )

    served = await client.get(f"/api/v1/projects/scans/{scan_id}/results", headers=member_auth_headers)

    assert served.status_code == 200, served.text
    assert sorted((set(row), row["analyzer_name"], row["source"]) for row in served.json()) == [
        ({"id", "scan_id", "analyzer_name", "source", "created_at"}, "kics", None),
        ({"id", "scan_id", "analyzer_name", "source", "created_at"}, "trufflehog", None),
    ]


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_a_rescan_shares_the_result_file_and_the_reaper_keeps_it_until_both_rows_are_gone(
    client, db, api_key_headers, monkeypatch
):
    resp = await client.post("/api/v1/ingest/kics", json={**_RUN, "queries": [_KICS_QUERY]}, headers=api_key_headers)
    scan_id = resp.json()["scan_id"]
    rescan = Scan(id="rescan-1", project_id="p", branch="main", is_rescan=True, original_scan_id=scan_id)
    await _carry_over_external_results("rescan-1", rescan, db)
    [original] = await _rows(db, scan_id)
    [copy] = await _rows(db, "rescan-1")
    file_id = ObjectId(original["result_gridfs_id"])
    monkeypatch.setattr("app.services.gridfs_maintenance.ARCHIVE_ORPHAN_MIN_AGE_HOURS", -1)

    await db.analysis_results.delete_one({"_id": original["_id"]})
    await reap_orphan_gridfs_files(db)
    kept = await db["fs.files"].count_documents({"_id": file_id})
    await db.analysis_results.delete_one({"_id": copy["_id"]})
    await reap_orphan_gridfs_files(db)

    assert copy["result_gridfs_id"] == original["result_gridfs_id"]
    assert (kept, await db["fs.files"].count_documents({"_id": file_id})) == (1, 0)


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
