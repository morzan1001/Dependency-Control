"""The orphan reaper deletes GridFS files and chunks nothing references once they outlive the safety window."""

import asyncio
import json
from collections.abc import Awaitable, Callable
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import AsyncMock

import pytest
from bson import ObjectId
from motor.motor_asyncio import AsyncIOMotorGridFSBucket

from app.core.constants import API_KEY_SURFACE_ADHOC, ARCHIVE_BATCH_SIZE
from app.core.init_db import create_indexes
from app.core.permissions import Permissions
from app.core.worker import AnalysisWorkerManager
from app.models.project import Project
from app.repositories.analysis_results import AnalysisResultRepository
from app.repositories.api_keys import ApiKeyRepository
from app.services.gridfs_maintenance import reap_orphan_gridfs_files, upload_gridfs_json
from app.services.scan_cascade import delete_scans_and_related_data
from tests.helpers.compliance import generated_report

_FIXTURES = Path(__file__).parents[1] / "fixtures"
_SBOM = json.loads((_FIXTURES / "sbom/npmpeer.syft.cdx.json").read_text())
_KICS_REPORT = json.loads((_FIXTURES / "iac/kics_2.1.20_results.json").read_text())
_RUN = {"pipeline_id": 717171, "commit_hash": "e" * 40, "branch": "main"}
# madge --json --include-npm with the job's package.json merged in
_MADGE = {"index.js": ["node_modules/lodash/lodash.js", "src/util.js"], "__analyzed_modules__": ["lodash"]}
# The driver writes an unfinished upload's chunks only once it has buffered 48 MB of them.
_PAST_THE_UPLOAD_BUFFER = b"x" * (50 * 1024 * 1024)

# Each writer stores one reference the way production does and returns the file id and a deleter of the reference.
_Writer = Callable[..., Awaitable[tuple[str, Callable[[], Awaitable[object]]]]]


async def _ingested_sbom(client, db, api_key_headers, monkeypatch):
    resp = await client.post("/api/v1/ingest", json={**_RUN, "sboms": [_SBOM]}, headers=api_key_headers)
    assert resp.status_code == 202, resp.text
    scan_id = resp.json()["scan_id"]
    [ref] = (await db.scans.find_one({"_id": scan_id}))["sbom_refs"]
    return ref["gridfs_id"], lambda: db.scans.delete_one({"_id": scan_id})


async def _saved_result(client, db, api_key_headers, monkeypatch):
    await AnalysisResultRepository(db).save_result("scan-1", "kics", _KICS_REPORT)
    row = await db.analysis_results.find_one({"scan_id": "scan-1"})
    return row["result_gridfs_id"], lambda: db.analysis_results.delete_one({"_id": row["_id"]})


async def _generated_artifact(client, db, api_key_headers, monkeypatch):
    report = await generated_report(db, monkeypatch)
    return report.artifact_gridfs_id, lambda: db.compliance_reports.delete_one({"_id": report.id})


async def _uploaded_callgraph(client, db, api_key_headers, monkeypatch):
    project = Project(id="test-project-id", name="test-project")
    monkeypatch.setattr("app.api.deps._authenticate_ci", AsyncMock(return_value=project))
    resp = await client.post(
        f"/api/v1/projects/{project.id}/callgraph",
        json={**_RUN, "format": "madge", "data": _MADGE},
        headers={"Job-Token": "gitlab.oidc.token"},
    )
    assert resp.status_code == 200, resp.text
    row = await db.callgraphs.find_one({"project_id": project.id})
    return row["graph_gridfs_id"], lambda: db.callgraphs.delete_one({"_id": row["_id"]})


async def _queued_adhoc_job(client, db, monkeypatch, manager: AnalysisWorkerManager) -> str:
    owner = "adhoc-user"
    monkeypatch.setattr("app.api.v1.endpoints.analyze.worker_manager", manager)
    _, token = await ApiKeyRepository(db).create(owner, "ci", [API_KEY_SURFACE_ADHOC], 30)
    await db.users.insert_one(
        {"_id": owner, "username": owner, "email": f"{owner}@example.com", "permissions": [Permissions.ANALYZE_ADHOC]}
    )
    resp = await client.post(
        "/api/v1/analyze",
        json={"sboms": [_SBOM], "analyzers": ["license_compliance"], "apply_global_waivers": False},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 202, resp.text
    return resp.json()["job_id"]


async def _adhoc_input(client, db, api_key_headers, monkeypatch):
    job_id = await _queued_adhoc_job(client, db, monkeypatch, AnalysisWorkerManager(num_workers=1))
    job = await db.adhoc_jobs.find_one({"_id": job_id})
    return job["input_file_id"], lambda: db.adhoc_jobs.delete_one({"_id": job_id})


async def _adhoc_result(client, db, api_key_headers, monkeypatch):
    async def _get_database():
        return db

    manager = AnalysisWorkerManager(num_workers=1)
    monkeypatch.setattr("app.core.worker.get_database", _get_database)
    job_id = await _queued_adhoc_job(client, db, monkeypatch, manager)
    worker = asyncio.create_task(manager.worker("reaper-test"))
    await manager.queue.join()
    worker.cancel()
    await asyncio.gather(worker, return_exceptions=True)
    job = await db.adhoc_jobs.find_one({"_id": job_id})
    return job["result_file_id"], lambda: db.adhoc_jobs.delete_one({"_id": job_id})


_WRITERS: dict[tuple[str, str], _Writer] = {
    ("scans", "sbom_refs.gridfs_id"): _ingested_sbom,
    ("analysis_results", "result_gridfs_id"): _saved_result,
    ("compliance_reports", "artifact_gridfs_id"): _generated_artifact,
    ("callgraphs", "graph_gridfs_id"): _uploaded_callgraph,
    ("adhoc_jobs", "input_file_id"): _adhoc_input,
    ("adhoc_jobs", "result_file_id"): _adhoc_result,
}


def _every_file_outlived_the_window(monkeypatch) -> None:
    monkeypatch.setattr("app.services.gridfs_maintenance.ARCHIVE_ORPHAN_MIN_AGE_HOURS", -1)


async def _file_ids(db) -> set[str]:
    return {str(doc["_id"]) async for doc in db["fs.files"].find({}, {"_id": 1})}


@pytest.mark.asyncio
@pytest.mark.live_mongo
@pytest.mark.parametrize(("collection", "field"), _WRITERS, ids=[f"{c}.{f}" for c, f in _WRITERS])
async def test_each_registry_field_protects_its_file(
    client, db, api_key_headers, owner_auth_headers_proj, monkeypatch, collection, field
):
    file_id, delete_reference = await _WRITERS[collection, field](client, db, api_key_headers, monkeypatch)
    _every_file_outlived_the_window(monkeypatch)

    await reap_orphan_gridfs_files(db)
    kept = file_id in await _file_ids(db)
    await delete_reference()
    await reap_orphan_gridfs_files(db)

    assert (kept, file_id in await _file_ids(db)) == (True, False)


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_a_file_younger_than_the_window_is_kept(db):
    file_id = await upload_gridfs_json(db, "result.json", _KICS_REPORT)

    assert await reap_orphan_gridfs_files(db) == 0
    assert await _file_ids(db) == {file_id}


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_the_reaper_walks_more_than_one_batch(db, monkeypatch):
    repo = AnalysisResultRepository(db)
    orphans = set()
    for i in range(2 * ARCHIVE_BATCH_SIZE + 1):
        orphans.add(await upload_gridfs_json(db, f"orphan-{i}.json", {"findings": []}))
        await repo.save_result(f"scan-{i}", "trufflehog", {"findings": []})
    referenced = set(await db.analysis_results.distinct("result_gridfs_id"))
    _every_file_outlived_the_window(monkeypatch)

    deleted = await reap_orphan_gridfs_files(db)

    assert (deleted, await _file_ids(db)) == (len(orphans), referenced)


@pytest.mark.asyncio
@pytest.mark.live_mongo
@pytest.mark.parametrize(("collection", "field"), _WRITERS, ids=[f"{c}.{f}" for c, f in _WRITERS])
async def test_each_registry_lookup_is_an_index_scan(db, collection, field):
    await create_indexes(db)

    explain = await db.command(
        {"explain": {"distinct": collection, "key": field, "query": {field: {"$in": [str(ObjectId())]}}}}
    )

    assert f"'indexName': '{field}_1'" in str(explain["queryPlanner"]["winningPlan"])


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_deleting_scans_leaves_their_files_to_the_reaper(client, db, api_key_headers, monkeypatch):
    file_id, _ = await _ingested_sbom(client, db, api_key_headers, monkeypatch)
    scan_id = (await db.scans.find_one({}, {"_id": 1}))["_id"]

    await delete_scans_and_related_data(db, [scan_id])
    kept = file_id in await _file_ids(db)
    _every_file_outlived_the_window(monkeypatch)
    await reap_orphan_gridfs_files(db)

    assert (kept, file_id in await _file_ids(db)) == (True, False)


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_the_chunks_of_an_aborted_upload_are_reaped(db, monkeypatch):
    aborted = AsyncIOMotorGridFSBucket(db).open_upload_stream("sbom.json")
    await aborted.write(_PAST_THE_UPLOAD_BUFFER)
    written = await db["fs.chunks"].count_documents({"files_id": aborted._id})
    await AnalysisResultRepository(db).save_result("scan-1", "kics", _KICS_REPORT)
    kept_file = ObjectId((await db.analysis_results.find_one({}))["result_gridfs_id"])
    _every_file_outlived_the_window(monkeypatch)

    await reap_orphan_gridfs_files(db)

    assert written > 0
    assert await db["fs.chunks"].count_documents({"files_id": aborted._id}) == 0
    assert await db["fs.chunks"].count_documents({"files_id": kept_file}) == 1


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_a_restore_uploading_under_its_archived_id_keeps_its_chunks(db):
    archived_id = ObjectId.from_datetime(datetime.now(timezone.utc) - timedelta(days=30))
    restoring = AsyncIOMotorGridFSBucket(db).open_upload_stream_with_id(archived_id, "restored.json")
    await restoring.write(_PAST_THE_UPLOAD_BUFFER)
    written = await db["fs.chunks"].count_documents({"files_id": archived_id})

    await reap_orphan_gridfs_files(db)

    assert written > 0
    assert await db["fs.chunks"].count_documents({"files_id": archived_id}) == written
