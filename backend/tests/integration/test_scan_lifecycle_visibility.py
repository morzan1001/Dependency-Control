"""Partially-failed scans must surface the loss: status completed_with_errors, error text, failed_analyzers."""

from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio

from app.core.constants import SCAN_STATUS_COMPLETED, SCAN_STATUS_COMPLETED_WITH_ERRORS, SCAN_STATUS_FAILED
from app.core.init_db import create_indexes
from app.models.project import Project, Scan
from app.repositories.findings import FindingRepository
from app.services.analysis import engine
from app.services.analysis.engine import run_analysis
from app.services.crypto_policy.seeder import seed_crypto_policies
from tests.helpers.analyzers import serve_analyzer
from tests.helpers.sboms import store_sbom

_PROJECT_ID = "test-project-id"
_WORKER = "pod-a/worker-0"

# 24-hex-char GridFS ObjectIds, as stored in prod sbom_refs.
_FILE_ID_A = "69d5332257c8763c8d8c82d7"
_FILE_ID_B = "69d5332357c8763c8d8c82de"

_SBOM_A = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "components": [
        {
            "type": "library",
            "bom-ref": "pkg:pypi/requests@2.31.0",
            "name": "requests",
            "version": "2.31.0",
            "purl": "pkg:pypi/requests@2.31.0",
        }
    ],
}
_SBOM_B = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "components": [
        {
            "type": "library",
            "bom-ref": "pkg:pypi/flask@3.0.0",
            "name": "flask",
            "version": "3.0.0",
            "purl": "pkg:pypi/flask@3.0.0",
        }
    ],
}


def _gridfs_ref(file_id: str) -> dict:
    # Mirrors the sbom_refs entries stored in prod scans.
    return {
        "storage": "gridfs",
        "file_id": file_id,
        "filename": f"sbom-{file_id}.json",
        "type": "gridfs_reference",
        "gridfs_id": file_id,
    }


@pytest_asyncio.fixture
async def _stored_sboms(db):
    await create_indexes(db)
    await store_sbom(db, _SBOM_A, _FILE_ID_A)
    await store_sbom(db, _SBOM_B, _FILE_ID_B)


@pytest.fixture
def _no_gridfs(monkeypatch):
    monkeypatch.setattr(engine, "AsyncIOMotorGridFSBucket", lambda _db: None)


async def _seed_scan(db, sbom_refs: list[dict], scan_type: str | None = None) -> str:
    scan = Scan(
        project_id=_PROJECT_ID,
        branch="main",
        sbom_refs=sbom_refs,
        status="processing",
        worker_id=_WORKER,
        scan_type=scan_type,
    )
    await db.scans.insert_one(scan.model_dump(by_alias=True))
    return scan.id


async def _seed_project(db, latest_scan_id: str | None = None) -> None:
    project = Project(id=_PROJECT_ID, name="test-project", latest_scan_id=latest_scan_id)
    await db.projects.insert_one(project.model_dump(by_alias=True))


class _FailingAnalyzer:
    async def analyze(self, sbom, settings=None, parsed_components=None):
        raise RuntimeError("analyzer exploded")


class _ErrorResultAnalyzer:
    """Returns an error-shaped result that aggregates into one SYSTEM_WARNING finding."""

    async def analyze(self, sbom, settings=None, parsed_components=None):
        return {"error": "controlled scanner error"}


class _CliTimeoutAnalyzer:
    """Real CLI failure shape: cli_base returns error dicts instead of raising (dominant prod case)."""

    async def analyze(self, sbom, settings=None, parsed_components=None):
        return {"error": "grype analysis failed", "details": "grype timed out after 300 seconds"}


class _GrypeVulnAnalyzer:
    """Grype's native result shape, so the run produces a vulnerability finding to enrich."""

    async def analyze(self, sbom, settings=None, parsed_components=None):
        return {
            "matches": [
                {
                    "vulnerability": {
                        "id": "CVE-2023-32681",
                        "severity": "Medium",
                        "description": "Proxy-Authorization header leak in requests",
                        "fix": {"versions": ["2.31.0"], "state": "fixed"},
                    },
                    "artifact": {
                        "name": "requests",
                        "version": "2.30.0",
                        "purl": "pkg:pypi/requests@2.30.0",
                    },
                }
            ]
        }


class _PartialResultAnalyzer:
    """Mimics W15: reports success but flags skipped coverage."""

    async def analyze(self, sbom, settings=None, parsed_components=None):
        return {"osv_vulnerabilities": [], "partial_components_skipped": 7}


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_w12_failed_analyzer_marks_scan_completed_with_errors(db, _stored_sboms, monkeypatch):
    serve_analyzer(monkeypatch, "boom", _FailingAnalyzer())
    await _seed_project(db)
    scan_id = await _seed_scan(db, [_gridfs_ref(_FILE_ID_A)])

    assert (
        await run_analysis(scan_id, [_gridfs_ref(_FILE_ID_A)], ["boom"], db, worker_id=_WORKER)
        == SCAN_STATUS_COMPLETED_WITH_ERRORS
    )

    scan = await db.scans.find_one({"_id": scan_id})
    assert scan["status"] == "completed_with_errors"
    assert "boom" in scan["error"]
    assert scan["failed_analyzers"] == ["boom"]
    assert scan["latest_run"]["status"] == "completed_with_errors"
    # The failure is also visible as a persisted finding.
    error_findings = [d async for d in db.findings.find({"scan_id": scan_id, "finding_id": "SCAN-ERROR-boom"})]
    assert len(error_findings) == 1


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_w12_cli_error_result_marks_scan_completed_with_errors(db, _stored_sboms, monkeypatch):
    """CLI analyzers (grype/trivy) report timeouts as error dicts, not exceptions — 95% of prod failures."""
    serve_analyzer(monkeypatch, "grype", _CliTimeoutAnalyzer())
    await _seed_project(db)
    scan_id = await _seed_scan(db, [_gridfs_ref(_FILE_ID_A)])

    assert (
        await run_analysis(scan_id, [_gridfs_ref(_FILE_ID_A)], ["grype"], db, worker_id=_WORKER)
        == SCAN_STATUS_COMPLETED_WITH_ERRORS
    )

    scan = await db.scans.find_one({"_id": scan_id})
    assert scan["status"] == "completed_with_errors"
    assert scan["failed_analyzers"] == ["grype"]
    error_findings = [d async for d in db.findings.find({"scan_id": scan_id, "finding_id": "SCAN-ERROR-grype"})]
    assert len(error_findings) == 1


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_w12_error_shaped_external_result_marks_scan_completed_with_errors(db, _stored_sboms):
    await _seed_project(db)
    scan_id = await _seed_scan(db, [_gridfs_ref(_FILE_ID_A)])
    await db.analysis_results.insert_one(
        {
            "_id": "res-1",
            "scan_id": scan_id,
            "analyzer_name": "trufflehog",
            "result": {"error": "scanner container OOM-killed"},
        }
    )

    assert (
        await run_analysis(scan_id, [_gridfs_ref(_FILE_ID_A)], [], db, worker_id=_WORKER)
        == SCAN_STATUS_COMPLETED_WITH_ERRORS
    )

    scan = await db.scans.find_one({"_id": scan_id})
    assert scan["status"] == "completed_with_errors"
    assert scan["failed_analyzers"] == ["trufflehog"]


def test_enrichment_post_processor_failures_do_not_flip_the_status():
    outcomes = engine._analyzer_outcomes(
        ["grype: Failed", "epss_kev: Failed", "reachability: Failed", "osv: Partial (7 component(s) were not scanned)"]
    )
    assert engine._failed_analyzer_names(outcomes) == (["grype", "osv"], ["epss_kev", "reachability"])


class _PartialOnTheSecondSbom:
    def __init__(self):
        self.calls = 0

    async def analyze(self, sbom, settings=None, parsed_components=None):
        self.calls += 1
        if self.calls == 1:
            return {"osv_vulnerabilities": []}
        return {"osv_vulnerabilities": [], "partial_components_skipped": 7}


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_a_two_sbom_run_announces_each_analyzer_once_with_its_worst_outcome(db, _stored_sboms, monkeypatch):
    announced: list[dict[str, str]] = []

    async def _capture(project_id, scan_id, scan_doc, stats, status, error, failed, findings, analyzer_outcomes, db):
        announced.append(analyzer_outcomes)

    monkeypatch.setattr(engine, "_send_integrations_and_notifications", _capture)
    serve_analyzer(monkeypatch, "osv", _PartialOnTheSecondSbom())
    await _seed_project(db)
    refs = [_gridfs_ref(_FILE_ID_A), _gridfs_ref(_FILE_ID_B)]
    scan_id = await _seed_scan(db, refs)

    assert await run_analysis(scan_id, refs, ["osv"], db, worker_id=_WORKER) == SCAN_STATUS_COMPLETED_WITH_ERRORS

    assert announced == [{"osv": "Partial (7 component(s) were not scanned)"}]


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_enrichment_failure_is_recorded_on_the_scan(db, _stored_sboms, monkeypatch):
    """An EPSS/KEV outage writes no analysis_results document (the write sits inside the
    try) and must not change the status, so the scan field is its only queryable trace."""

    async def _enrichment_outage(*_args, **_kwargs):
        raise RuntimeError("EPSS feed unreachable")

    monkeypatch.setattr(
        "app.services.analysis.engine.vulnerability_enrichment_service.enrich_findings", _enrichment_outage
    )
    serve_analyzer(monkeypatch, "grype", _GrypeVulnAnalyzer())
    await _seed_project(db)
    scan_id = await _seed_scan(db, [_gridfs_ref(_FILE_ID_A)])

    assert (
        await run_analysis(scan_id, [_gridfs_ref(_FILE_ID_A)], ["grype", "epss_kev"], db, worker_id=_WORKER)
        == SCAN_STATUS_COMPLETED
    )

    scan = await db.scans.find_one({"_id": scan_id})
    assert scan["enrichment_failures"] == ["epss_kev"]
    assert scan["status"] == "completed", "a post-processor outage loses metadata, not findings"
    assert scan["failed_analyzers"] is None
    assert await db.analysis_results.count_documents({"scan_id": scan_id, "analyzer_name": "epss_kev"}) == 0


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_a_clean_scan_records_no_enrichment_failures(db, _stored_sboms, monkeypatch):
    serve_analyzer(monkeypatch, "grype", _GrypeVulnAnalyzer())
    await _seed_project(db)
    scan_id = await _seed_scan(db, [_gridfs_ref(_FILE_ID_A)])

    assert (
        await run_analysis(scan_id, [_gridfs_ref(_FILE_ID_A)], ["grype", "epss_kev"], db, worker_id=_WORKER)
        == SCAN_STATUS_COMPLETED
    )

    scan = await db.scans.find_one({"_id": scan_id})
    assert scan["enrichment_failures"] is None


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_w12_scan_with_errors_still_becomes_project_latest(db, _stored_sboms, monkeypatch):
    serve_analyzer(monkeypatch, "boom", _FailingAnalyzer())
    await _seed_project(db)
    scan_id = await _seed_scan(db, [_gridfs_ref(_FILE_ID_A)])

    assert (
        await run_analysis(scan_id, [_gridfs_ref(_FILE_ID_A)], ["boom"], db, worker_id=_WORKER)
        == SCAN_STATUS_COMPLETED_WITH_ERRORS
    )

    project = await db.projects.find_one({"_id": _PROJECT_ID})
    assert project["latest_scan_id"] == scan_id


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_w15_partial_analyzer_result_marks_scan_completed_with_errors(db, _stored_sboms, monkeypatch):
    serve_analyzer(monkeypatch, "osv", _PartialResultAnalyzer())
    await _seed_project(db)
    scan_id = await _seed_scan(db, [_gridfs_ref(_FILE_ID_A)])

    assert (
        await run_analysis(scan_id, [_gridfs_ref(_FILE_ID_A)], ["osv"], db, worker_id=_WORKER)
        == SCAN_STATUS_COMPLETED_WITH_ERRORS
    )

    scan = await db.scans.find_one({"_id": scan_id})
    assert scan["status"] == "completed_with_errors"
    assert "osv" in scan["error"]
    assert scan["failed_analyzers"] == ["osv"]
    error_findings = [d async for d in db.findings.find({"scan_id": scan_id, "finding_id": "SCAN-ERROR-osv"})]
    assert len(error_findings) == 1, "partial coverage must be visible in the findings list"
    assert error_findings[0]["description"].startswith("Scanner 'osv' returned partial results: ")


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_a_crypto_evaluator_failing_with_an_empty_message_still_counts_as_failed(db, monkeypatch):
    await create_indexes(db)
    real_evaluators = engine.crypto_evaluators

    def _weak_key_times_out(catalog):
        def _raise(_assets, _policy):
            raise TimeoutError()  # str() of a bare TimeoutError is ""

        return {**real_evaluators(catalog), "crypto_weak_key": _raise}

    monkeypatch.setattr(engine, "crypto_evaluators", _weak_key_times_out)
    await seed_crypto_policies(db)
    await _seed_project(db)
    scan_id = await _seed_scan(db, sbom_refs=[], scan_type="cbom")

    assert await run_analysis(scan_id, [], [], db, worker_id=_WORKER) == SCAN_STATUS_COMPLETED_WITH_ERRORS

    scan = await db.scans.find_one({"_id": scan_id})
    assert scan["failed_analyzers"] == ["crypto_weak_key"]


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_k9_partial_gridfs_failure_marks_scan_completed_with_errors(db, _stored_sboms, monkeypatch):
    real_open = engine.open_gridfs_download_with_retry

    async def _fail_second_file(fs, file_id, **kwargs):
        if str(file_id) == _FILE_ID_B:
            raise OSError("transient gridfs outage")
        return await real_open(fs, file_id, **kwargs)

    monkeypatch.setattr(engine, "open_gridfs_download_with_retry", _fail_second_file)
    await _seed_project(db)
    refs = [_gridfs_ref(_FILE_ID_A), _gridfs_ref(_FILE_ID_B)]
    scan_id = await _seed_scan(db, refs)

    assert await run_analysis(scan_id, refs, [], db, worker_id=_WORKER) == SCAN_STATUS_COMPLETED_WITH_ERRORS

    scan = await db.scans.find_one({"_id": scan_id})
    assert scan["status"] == "completed_with_errors"
    assert "1 of 2 SBOMs failed to load" in scan["error"]


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_k9_all_gridfs_failures_still_mark_scan_failed(db, _stored_sboms, monkeypatch):
    async def _fail_all(fs, file_id, **_kwargs):
        raise OSError("gridfs outage")

    monkeypatch.setattr(engine, "open_gridfs_download_with_retry", _fail_all)
    await _seed_project(db)
    scan_id = await _seed_scan(db, [_gridfs_ref(_FILE_ID_A)])

    assert await run_analysis(scan_id, [_gridfs_ref(_FILE_ID_A)], [], db, worker_id=_WORKER) == SCAN_STATUS_FAILED

    scan = await db.scans.find_one({"_id": scan_id})
    assert scan["status"] == "failed"


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_k8_partial_findings_persistence_is_surfaced(db, _stored_sboms, monkeypatch):
    serve_analyzer(monkeypatch, "stub", _ErrorResultAnalyzer())

    async def _drop_all_docs(self, docs):
        return 0

    monkeypatch.setattr(FindingRepository, "replace_many_raw", _drop_all_docs)
    await _seed_project(db)
    scan_id = await _seed_scan(db, [_gridfs_ref(_FILE_ID_A)])

    assert (
        await run_analysis(scan_id, [_gridfs_ref(_FILE_ID_A)], ["stub"], db, worker_id=_WORKER)
        == SCAN_STATUS_COMPLETED_WITH_ERRORS
    )

    scan = await db.scans.find_one({"_id": scan_id})
    assert scan["status"] == "completed_with_errors"
    assert "0 of 1 findings" in scan["error"]
    assert scan["findings_count"] == 0, "findings_count must reflect what was persisted, not what was intended"


@pytest.mark.asyncio
async def test_k10_sast_only_scan_does_not_replace_project_latest(db, _no_gridfs):
    await _seed_project(db, latest_scan_id="previous-sbom-scan")
    previous = Scan(
        id="previous-sbom-scan",
        project_id=_PROJECT_ID,
        branch="main",
        status="completed",
        sbom_refs=[_gridfs_ref(_FILE_ID_A)],
        created_at=datetime.now(timezone.utc) - timedelta(hours=1),
    )
    await db.scans.insert_one(previous.model_dump(by_alias=True))
    scan_id = await _seed_scan(db, sbom_refs=[])

    assert await run_analysis(scan_id, [], [], db, worker_id=_WORKER) == SCAN_STATUS_COMPLETED

    scan = await db.scans.find_one({"_id": scan_id})
    assert scan["status"] == "completed"
    project = await db.projects.find_one({"_id": _PROJECT_ID})
    assert project["latest_scan_id"] == "previous-sbom-scan", (
        "a scan that never received an SBOM must not wipe the project's SBOM-derived picture"
    )


@pytest.mark.asyncio
async def test_k10_sast_only_scan_becomes_latest_when_project_has_none(db, _no_gridfs):
    await _seed_project(db, latest_scan_id=None)
    scan_id = await _seed_scan(db, sbom_refs=[])

    assert await run_analysis(scan_id, [], [], db, worker_id=_WORKER) == SCAN_STATUS_COMPLETED

    project = await db.projects.find_one({"_id": _PROJECT_ID})
    assert project["latest_scan_id"] == scan_id, "SAST-only projects must still get a latest scan"
