"""Ingest stores each recognized SBOM in GridFS and nothing else; the analysis engine writes the
dependency inventory, and a re-ingest replaces sbom_refs so superseded uploads can be reaped."""

import asyncio
import json
import logging
from pathlib import Path
from unittest.mock import patch

import pytest
from motor.motor_asyncio import AsyncIOMotorGridFSBucket
from pymongo.errors import AutoReconnect

from app.core.init_db import create_indexes
from app.core.worker import AnalysisWorkerManager
from app.repositories.dependencies import DependencyRepository
from app.services import scan_manager
from app.services.analysis import engine
from app.services.analysis.engine import _parse_and_track_sbom
from app.services.dependency_store import store_scan_dependencies
from app.services.gridfs_maintenance import gridfs_ref_id, load_gridfs_json, reap_orphan_gridfs_files
from app.services.sbom_parser import parse_sbom
from tests.integration.test_upload_uniformity import _syft_sbom

_PROJECT_ID = "test-project-id"
_SCAN_ID = "8e0d76a5-1291-5949-8e0d-0d90b4bd9e01"
_FIXTURES = Path(__file__).parents[1] / "fixtures"
_MIB = 1024 * 1024
_POLL_ATTEMPTS = 600
_POLL_INTERVAL_SECONDS = 0.1
_INGEST_RESPONSE_KEYS = {"status", "scan_id", "message", "sboms_processed", "sboms_failed"}


def _fixture(path: str) -> dict:
    return json.loads((_FIXTURES / path).read_text())


def _cyclonedx(components: list[dict]) -> dict:
    return {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": components}


_GOOD_SBOM = _cyclonedx(
    [
        {
            "type": "library",
            "bom-ref": "pkg:pypi/requests@2.31.0",
            "name": "requests",
            "version": "2.31.0",
            "purl": "pkg:pypi/requests@2.31.0",
        }
    ]
)


@pytest.fixture
def worker_after_ingest(running_worker, monkeypatch):
    """The running worker, while ingest queues its job where nothing takes it: the test decides when the engine runs."""
    monkeypatch.setattr(scan_manager, "worker_manager", AnalysisWorkerManager(num_workers=1))
    return running_worker


async def _analyse(db, worker: AnalysisWorkerManager, scan_id: str) -> dict:
    await create_indexes(db)
    await db.projects.update_one({"_id": _PROJECT_ID}, {"$set": {"active_analyzers": ["license_compliance"]}})
    await worker.add_job(scan_id)
    for _ in range(_POLL_ATTEMPTS):
        scan = await db.scans.find_one({"_id": scan_id})
        if scan["status"] not in ("pending", "processing"):
            return scan
        await asyncio.sleep(_POLL_INTERVAL_SECONDS)
    raise AssertionError(f"scan {scan_id} never finished")


def _run(sboms: list[dict], pipeline_id: int = 424243, **extra) -> dict:
    return {"pipeline_id": pipeline_id, "commit_hash": "c" * 40, "branch": "main", "sboms": sboms, **extra}


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_an_ingest_only_stores_the_sbom_and_the_engine_writes_its_dependencies(
    client, db, api_key_headers, worker_after_ingest
):
    sbom = _fixture("sbom/mono.syft.json")

    resp = await client.post("/api/v1/ingest", json=_run([sbom]), headers=api_key_headers)

    assert resp.status_code == 202, resp.text
    body = resp.json()
    assert set(body) == _INGEST_RESPONSE_KEYS
    scan_id = body["scan_id"]
    assert (body["sboms_processed"], body["sboms_failed"]) == (1, 0)
    assert await db["fs.files"].count_documents({"metadata.scan_id": scan_id}) == 1
    assert await db.dependencies.count_documents({}) == 0

    scan = await _analyse(db, worker_after_ingest, scan_id)

    assert scan["status"] == "completed", scan.get("error")
    stored = await db.dependencies.count_documents({"scan_id": scan_id})
    assert stored == len(parse_sbom(sbom).dependencies) == 9


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_an_sbom_past_25_mib_is_stored_whole_and_its_dependencies_come_from_the_engine(
    client, db, api_key_headers, worker_after_ingest
):
    payload = _syft_sbom()
    [sbom] = payload["sboms"]
    assert len(json.dumps(sbom)) > 25 * _MIB

    resp = await client.post("/api/v1/ingest", json=payload, headers=api_key_headers)

    assert resp.status_code == 202, resp.text
    scan_id = resp.json()["scan_id"]
    [ref] = (await db.scans.find_one({"_id": scan_id}))["sbom_refs"]
    assert await load_gridfs_json(AsyncIOMotorGridFSBucket(db), gridfs_ref_id(ref)) == sbom
    assert await db.dependencies.count_documents({}) == 0

    scan = await _analyse(db, worker_after_ingest, scan_id)

    assert scan["status"] == "completed", scan.get("error")
    stored = await db.dependencies.count_documents({"scan_id": scan_id})
    assert stored == len(parse_sbom(sbom).dependencies) > len(_fixture("sbom/mono.syft.json")["artifacts"])


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_a_recognized_sbom_that_does_not_parse_is_accepted_and_its_scan_completes_with_errors(
    client, db, api_key_headers, worker_after_ingest
):
    sbom = {**_fixture("sbom/mono.syft.cdx.json"), "metadata": []}

    resp = await client.post("/api/v1/ingest", json=_run([sbom]), headers=api_key_headers)

    assert resp.status_code == 202, resp.text
    assert (resp.json()["sboms_processed"], resp.json()["sboms_failed"]) == (1, 0)
    scan = await _analyse(db, worker_after_ingest, resp.json()["scan_id"])
    assert scan["status"] == "completed_with_errors"
    assert "1 of 1 SBOMs failed to parse" in scan["error"]


@pytest.mark.asyncio
async def test_a_payload_with_an_unparsed_sbom_keeps_the_previous_inventory(db):
    """A re-run cannot swap the stored complete inventory for the partial one of a payload with a failed SBOM."""
    repo = DependencyRepository(db)
    previous = parse_sbom(_fixture("sbom/mono.syft.json"))
    await store_scan_dependencies([previous], _PROJECT_ID, _SCAN_ID, repo)

    stored = await store_scan_dependencies(
        [parse_sbom(_fixture("sbom/uvdev.syft.cdx.json")), None], _PROJECT_ID, _SCAN_ID, repo
    )

    assert stored is None
    names = {d["name"] async for d in db.dependencies.find({"scan_id": _SCAN_ID})}
    assert names == {dep.name for dep in previous.dependencies}


def test_the_skipped_components_and_their_reasons_reach_the_engine_log(caplog):
    with caplog.at_level(logging.INFO, logger="app.services.analysis.engine"):
        _parse_and_track_sbom(_fixture("sbom/mono.syft.json"))

    assert "skipped=3" in caplog.text
    assert "'file': 2" in caplog.text
    assert "'root-component': 1" in caplog.text


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_w14_reingest_replaces_sbom_refs_and_the_reaper_frees_the_superseded_file(
    client, db, api_key_headers, monkeypatch
):
    payload = {
        "pipeline_id": 424242,
        "commit_hash": "b" * 40,
        "branch": "main",
        "project_url": "https://example.invalid/p",
        "sboms": [_GOOD_SBOM],
    }

    resp1 = await client.post("/api/v1/ingest", json=payload, headers=api_key_headers)
    assert resp1.status_code == 202, resp1.text
    scan_id = resp1.json()["scan_id"]
    scan = await db.scans.find_one({"_id": scan_id})
    first_refs = scan["sbom_refs"]
    assert len(first_refs) == 1

    resp2 = await client.post("/api/v1/ingest", json=payload, headers=api_key_headers)
    assert resp2.status_code == 202, resp2.text
    assert resp2.json()["scan_id"] == scan_id, "same pipeline+commit must map to the same scan"

    scan = await db.scans.find_one({"_id": scan_id})
    assert len(scan["sbom_refs"]) == 1, f"re-ingest must replace sbom_refs, got {len(scan['sbom_refs'])}"
    assert scan["sbom_refs"][0]["gridfs_id"] != first_refs[0]["gridfs_id"]

    monkeypatch.setattr("app.services.gridfs_maintenance.ARCHIVE_ORPHAN_MIN_AGE_HOURS", -1)
    assert await reap_orphan_gridfs_files(db) == 1
    assert [str(doc["_id"]) async for doc in db["fs.files"].find()] == [scan["sbom_refs"][0]["gridfs_id"]]


@pytest.mark.asyncio
async def test_a_reingest_during_the_analysis_marks_the_sbom_replaced_and_keeps_the_files_it_reads(
    client, db, api_key_headers, fake_gridfs
):
    payload = {"pipeline_id": 424244, "commit_hash": "d" * 40, "branch": "main", "sboms": [_GOOD_SBOM]}

    scan_id = (await client.post("/api/v1/ingest", json=payload, headers=api_key_headers)).json()["scan_id"]
    await db.scans.update_one({"_id": scan_id}, {"$set": {"status": "processing"}})
    resp = await client.post("/api/v1/ingest", json=payload, headers=api_key_headers)

    assert resp.status_code == 202, resp.text
    scan = await db.scans.find_one({"_id": scan_id})
    assert (scan["status"], scan["sbom_generation"]) == ("processing", 2)
    assert await db["fs.files"].count_documents({}) == 2, "the running analysis still reads the old upload"


async def _fail_through_the_worker(client, db, api_key_headers, worker: AnalysisWorkerManager) -> str:
    resp = await client.post("/api/v1/ingest", json=_run([_GOOD_SBOM]), headers=api_key_headers)
    assert resp.status_code == 202, resp.text
    scan_id = resp.json()["scan_id"]
    with patch.object(engine, "store_scan_dependencies", side_effect=AutoReconnect("primary stepped down")):
        scan = await _analyse(db, worker, scan_id)
    assert (scan["status"], scan["error"]) == ("failed", "primary stepped down")
    return scan_id


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_an_sbom_re_upload_re_analyses_a_failed_scan(client, db, api_key_headers, worker_after_ingest):
    scan_id = await _fail_through_the_worker(client, db, api_key_headers, worker_after_ingest)

    resp = await client.post("/api/v1/ingest", json=_run([_GOOD_SBOM]), headers=api_key_headers)

    assert (resp.status_code, resp.json()["scan_id"]) == (202, scan_id), resp.text
    scan = await _analyse(db, worker_after_ingest, scan_id)
    assert scan["status"] == "completed", scan.get("error")
    assert "error" not in scan
    await worker_after_ingest.queue.join()
    assert (await db.projects.find_one({"_id": _PROJECT_ID}))["latest_scan_id"] == scan_id


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_scanner_and_cbom_uploads_leave_a_failed_scan_failed(client, db, api_key_headers, worker_after_ingest):
    scan_id = await _fail_through_the_worker(client, db, api_key_headers, worker_after_ingest)

    secrets = await client.post("/api/v1/ingest/trufflehog", json=_run([], findings=[]), headers=api_key_headers)
    cbom = _fixture("cbom/legacy_crypto_mixed.json")
    crypto = await client.post("/api/v1/ingest/cbom", json=_run([], cbom=cbom), headers=api_key_headers)

    assert (secrets.status_code, crypto.status_code) == (200, 202), (secrets.text, crypto.text)
    assert secrets.json()["scan_id"] == crypto.json()["scan_id"] == scan_id
    assert (await db.scans.find_one({"_id": scan_id}))["status"] == "failed"


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_a_payload_whose_sboms_did_not_all_fail_is_accepted(client, db, api_key_headers):
    """Refusing the mixed payload would throw away the good SBOM and the scan row the pipeline's
    other analyzers attach their results to."""
    sboms = [_fixture("sbom/mono.syft.json"), _fixture("iac/kics_2.1.20_results.json")]

    resp = await client.post("/api/v1/ingest", json=_run(sboms), headers=api_key_headers)

    assert resp.status_code == 202, resp.text
    body = resp.json()
    assert (body["sboms_processed"], body["sboms_failed"]) == (1, 1)
    assert await db["fs.files"].count_documents({}) == 1
    assert await db.scans.find_one({"_id": body["scan_id"]}) is not None


@pytest.mark.asyncio
@pytest.mark.live_mongo
@pytest.mark.parametrize(
    "document",
    [_fixture("iac/kics_2.1.20_results.json"), {"$schema": None}],
    ids=["kics-report", "null-schema"],
)
async def test_a_payload_without_a_recognized_sbom_is_refused(client, db, api_key_headers, document):
    resp = await client.post("/api/v1/ingest", json=_run([document]), headers=api_key_headers)

    assert resp.status_code == 400, resp.text
    assert all(name in resp.json()["detail"] for name in ("CycloneDX", "SPDX", "Syft"))
    assert await db["fs.files"].count_documents({}) == 0
    assert await db.scans.count_documents({}) == 0


@pytest.mark.asyncio
async def test_a_freshly_ingested_scan_waits_in_the_status_the_worker_claims(client, db, api_key_headers, fake_gridfs):
    """The worker's atomic claim matches on 'pending' alone, so any other word parks the scan
    forever: it is queued, never analysed, and nothing reports it as stuck."""

    resp = await client.post("/api/v1/ingest", json=_run([_GOOD_SBOM]), headers=api_key_headers)
    assert resp.status_code == 202, resp.text

    scan = await db.scans.find_one({"_id": resp.json()["scan_id"]})
    assert scan["status"] == "pending"


@pytest.mark.asyncio
async def test_an_ingest_without_a_branch_name_is_filed_under_unknown(client, db, api_key_headers, fake_gridfs):
    """Every branch-scoped reader defaults the missing branch to 'unknown'; a scan stored under
    any other sentinel is grouped with nothing."""

    resp = await client.post("/api/v1/ingest", json=_run([_GOOD_SBOM], branch=""), headers=api_key_headers)
    assert resp.status_code == 202, resp.text

    scan = await db.scans.find_one({"_id": resp.json()["scan_id"]})
    assert scan["branch"] == "unknown"
