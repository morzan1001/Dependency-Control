"""Partially-failed scans must surface the loss: status completed_with_errors, error text, failed_analyzers."""

import json
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.models.project import Project, Scan
from app.repositories.findings import FindingRepository
from app.services.analysis import engine
from app.services.analysis.engine import run_analysis

_PROJECT_ID = "test-project-id"

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


def _fake_gridfs(sboms_by_file_id: dict[str, dict]) -> MagicMock:
    fs = MagicMock()

    async def _open(object_id):
        stream = MagicMock()
        stream.read = AsyncMock(return_value=json.dumps(sboms_by_file_id[str(object_id)]).encode())
        return stream

    fs.open_download_stream = AsyncMock(side_effect=_open)
    return fs


@pytest.fixture
def _gridfs_patched(monkeypatch):
    fs = _fake_gridfs({_FILE_ID_A: _SBOM_A, _FILE_ID_B: _SBOM_B})
    monkeypatch.setattr("app.services.analysis.engine.primary_gridfs_bucket", lambda _db: fs)
    return fs


async def _seed_scan(db, sbom_refs: list[dict], scan_type: str | None = None) -> str:
    scan = Scan(project_id=_PROJECT_ID, branch="main", sbom_refs=sbom_refs, status="processing", scan_type=scan_type)
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


class _PartialResultAnalyzer:
    """Mimics W15: reports success but flags skipped coverage."""

    async def analyze(self, sbom, settings=None, parsed_components=None):
        return {"osv_vulnerabilities": [], "partial_components_skipped": 7}


@pytest.mark.asyncio
async def test_w12_failed_analyzer_marks_scan_completed_with_errors(db, _gridfs_patched, monkeypatch):
    monkeypatch.setitem(engine.analyzers, "boom", _FailingAnalyzer())
    await _seed_project(db)
    scan_id = await _seed_scan(db, [_gridfs_ref(_FILE_ID_A)])

    assert await run_analysis(scan_id, [_gridfs_ref(_FILE_ID_A)], ["boom"], db) is True

    scan = await db.scans.find_one({"_id": scan_id})
    assert scan["status"] == "completed_with_errors"
    assert "boom" in scan["error"]
    assert scan["failed_analyzers"] == ["boom"]
    assert scan["latest_run"]["status"] == "completed_with_errors"
    # The failure is also visible as a persisted finding.
    error_findings = [d async for d in db.findings.find({"scan_id": scan_id, "finding_id": "SCAN-ERROR-boom"})]
    assert len(error_findings) == 1


@pytest.mark.asyncio
async def test_w12_scan_with_errors_still_becomes_project_latest(db, _gridfs_patched, monkeypatch):
    monkeypatch.setitem(engine.analyzers, "boom", _FailingAnalyzer())
    await _seed_project(db)
    scan_id = await _seed_scan(db, [_gridfs_ref(_FILE_ID_A)])

    assert await run_analysis(scan_id, [_gridfs_ref(_FILE_ID_A)], ["boom"], db) is True

    project = await db.projects.find_one({"_id": _PROJECT_ID})
    assert project["latest_scan_id"] == scan_id


@pytest.mark.asyncio
async def test_w15_partial_analyzer_result_marks_scan_completed_with_errors(db, _gridfs_patched, monkeypatch):
    monkeypatch.setitem(engine.analyzers, "osv", _PartialResultAnalyzer())
    await _seed_project(db)
    scan_id = await _seed_scan(db, [_gridfs_ref(_FILE_ID_A)])

    assert await run_analysis(scan_id, [_gridfs_ref(_FILE_ID_A)], ["osv"], db) is True

    scan = await db.scans.find_one({"_id": scan_id})
    assert scan["status"] == "completed_with_errors"
    assert "osv" in scan["error"]
    assert scan["failed_analyzers"] == ["osv"]
    error_findings = [d async for d in db.findings.find({"scan_id": scan_id, "finding_id": "SCAN-ERROR-osv"})]
    assert len(error_findings) == 1, "partial coverage must be visible in the findings list"


@pytest.mark.asyncio
async def test_k9_partial_gridfs_failure_marks_scan_completed_with_errors(db, _gridfs_patched, monkeypatch):
    async def _fail_second_file(fs, file_id, **_kwargs):
        if str(file_id) == _FILE_ID_B:
            raise OSError("transient gridfs outage")
        return await fs.open_download_stream(file_id)

    monkeypatch.setattr("app.services.analysis.engine.open_gridfs_download_with_retry", _fail_second_file)
    await _seed_project(db)
    refs = [_gridfs_ref(_FILE_ID_A), _gridfs_ref(_FILE_ID_B)]
    scan_id = await _seed_scan(db, refs)

    assert await run_analysis(scan_id, refs, [], db) is True

    scan = await db.scans.find_one({"_id": scan_id})
    assert scan["status"] == "completed_with_errors"
    assert "1 of 2 SBOMs failed to load" in scan["error"]


@pytest.mark.asyncio
async def test_k9_all_gridfs_failures_still_mark_scan_failed(db, _gridfs_patched, monkeypatch):
    async def _fail_all(fs, file_id, **_kwargs):
        raise OSError("gridfs outage")

    monkeypatch.setattr("app.services.analysis.engine.open_gridfs_download_with_retry", _fail_all)
    await _seed_project(db)
    scan_id = await _seed_scan(db, [_gridfs_ref(_FILE_ID_A)])

    assert await run_analysis(scan_id, [_gridfs_ref(_FILE_ID_A)], [], db) is True

    scan = await db.scans.find_one({"_id": scan_id})
    assert scan["status"] == "failed"


@pytest.mark.asyncio
async def test_k8_partial_findings_persistence_is_surfaced(db, _gridfs_patched, monkeypatch):
    monkeypatch.setitem(engine.analyzers, "stub", _ErrorResultAnalyzer())

    async def _drop_all_docs(self, docs):
        return 0

    monkeypatch.setattr(FindingRepository, "create_many_raw", _drop_all_docs)
    await _seed_project(db)
    scan_id = await _seed_scan(db, [_gridfs_ref(_FILE_ID_A)])

    assert await run_analysis(scan_id, [_gridfs_ref(_FILE_ID_A)], ["stub"], db) is True

    scan = await db.scans.find_one({"_id": scan_id})
    assert scan["status"] == "completed_with_errors"
    assert "0 of 1 findings" in scan["error"]
    assert scan["findings_count"] == 0, "findings_count must reflect what was persisted, not what was intended"


@pytest.mark.asyncio
async def test_k10_sast_only_scan_does_not_replace_project_latest(db, monkeypatch):
    fs = _fake_gridfs({})
    monkeypatch.setattr("app.services.analysis.engine.primary_gridfs_bucket", lambda _db: fs)
    await _seed_project(db, latest_scan_id="previous-sbom-scan")
    scan_id = await _seed_scan(db, sbom_refs=[])

    assert await run_analysis(scan_id, [], [], db) is True

    scan = await db.scans.find_one({"_id": scan_id})
    assert scan["status"] == "completed"
    project = await db.projects.find_one({"_id": _PROJECT_ID})
    assert project["latest_scan_id"] == "previous-sbom-scan", (
        "a scan that never received an SBOM must not wipe the project's SBOM-derived picture"
    )


@pytest.mark.asyncio
async def test_k10_sast_only_scan_becomes_latest_when_project_has_none(db, monkeypatch):
    fs = _fake_gridfs({})
    monkeypatch.setattr("app.services.analysis.engine.primary_gridfs_bucket", lambda _db: fs)
    await _seed_project(db, latest_scan_id=None)
    scan_id = await _seed_scan(db, sbom_refs=[])

    assert await run_analysis(scan_id, [], [], db) is True

    project = await db.projects.find_one({"_id": _PROJECT_ID})
    assert project["latest_scan_id"] == scan_id, "SAST-only projects must still get a latest scan"
