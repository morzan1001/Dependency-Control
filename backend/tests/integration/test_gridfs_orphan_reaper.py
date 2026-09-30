"""The orphan reaper deletes GridFS files and chunks nothing references once they outlive the safety window."""

import json
from collections.abc import Awaitable, Callable
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from bson import ObjectId
from motor.motor_asyncio import AsyncIOMotorGridFSBucket

from app.core.constants import ARCHIVE_BATCH_SIZE
from app.core.init_db import create_indexes
from app.repositories.analysis_results import AnalysisResultRepository
from app.services.gridfs_maintenance import _GRIDFS_REFERENCES, reap_orphan_gridfs_files, upload_gridfs_json
from app.services.scan_cascade import delete_scans_and_related_data
from tests.helpers.compliance import generated_report

_FIXTURES = Path(__file__).parents[1] / "fixtures"
_SBOM = json.loads((_FIXTURES / "sbom/npmpeer.syft.cdx.json").read_text())
_KICS_REPORT = json.loads((_FIXTURES / "iac/kics_2.1.20_results.json").read_text())
_RUN = {"pipeline_id": 717171, "commit_hash": "e" * 40, "branch": "main"}
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


_WRITERS: dict[str, _Writer] = {
    "scans": _ingested_sbom,
    "analysis_results": _saved_result,
    "compliance_reports": _generated_artifact,
}


def _every_file_outlived_the_window(monkeypatch) -> None:
    monkeypatch.setattr("app.services.gridfs_maintenance.ARCHIVE_ORPHAN_MIN_AGE_HOURS", -1)


async def _file_ids(db) -> set[str]:
    return {str(doc["_id"]) async for doc in db["fs.files"].find({}, {"_id": 1})}


@pytest.mark.asyncio
@pytest.mark.live_mongo
@pytest.mark.parametrize(("collection", "field"), _GRIDFS_REFERENCES, ids=[c for c, _ in _GRIDFS_REFERENCES])
async def test_each_registry_field_protects_its_file(
    client, db, api_key_headers, owner_auth_headers_proj, monkeypatch, collection, field
):
    file_id, delete_reference = await _WRITERS[collection](client, db, api_key_headers, monkeypatch)
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
@pytest.mark.parametrize(("collection", "field"), _GRIDFS_REFERENCES, ids=[c for c, _ in _GRIDFS_REFERENCES])
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
