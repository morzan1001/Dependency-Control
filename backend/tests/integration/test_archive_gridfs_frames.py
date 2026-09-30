"""An archive bundle carries every GridFS file of a scan as chunk frames, restored byte-identical under the same ids."""

import json
import tracemalloc
import zlib
from collections.abc import AsyncIterator
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from bson import ObjectId
from motor.motor_asyncio import AsyncIOMotorGridFSBucket
from pymongo.common import MAX_MESSAGE_SIZE

from app.api.v1.endpoints.ingest import _upload_sbom_to_gridfs
from app.core.constants import ARCHIVE_GRIDFS_CHUNK_FRAME
from app.models.archive import ArchiveMetadata
from app.models.project import Project, Scan
from app.repositories.analysis_results import AnalysisResultRepository
from app.repositories.archive_metadata import ArchiveMetadataRepository
from app.services import archive
from app.services.archive import archive_scan, restore_scan, stream_bundle_for_download
from app.services.archive_bundle import BundleFrames, BundleStats, json_line, read_bundle_frames
from app.services.gridfs_maintenance import make_gridfs_ref, reap_orphan_gridfs_files
from app.services.rescan import build_rescan
from app.services.scan_cascade import delete_scans_and_related_data
from app.services.scan_manager import deterministic_scan_id

_MIB = 1024 * 1024
_MONGO_DOCUMENT_LIMIT = 16 * _MIB
# pymongo reads fs.chunks in server batches of up to 16 MiB and holds one batch raw and decoded.
_PEAK_BOUND = 40 * _MIB
# GridIn buffers chunks up to one max-size message, then insert_many encodes that batch once more.
_RESTORE_PEAK_BOUND = 2 * MAX_MESSAGE_SIZE + 16 * _MIB
_FIXTURES = Path(__file__).parents[1] / "fixtures"
_KICS_REPORT = json.loads((_FIXTURES / "iac/kics_2.1.20_results.json").read_text())
_PROJECT_ID = "test-project-id"
_PIPELINE_ID = 7
_COMMIT = "f" * 40
_SCAN_ID = deterministic_scan_id(_PROJECT_ID, _PIPELINE_ID, _COMMIT)
_MADGE = {f"src/feature-{i}.ts": [f"../node_modules/pkg-{i % 40}/index.js", "src/shared.ts"] for i in range(400)}


def _sbom_fixture() -> dict[str, Any]:
    return json.loads((_FIXTURES / "sbom/uvdev.syft.cdx.json").read_text())


def _sbom_of(size: int) -> dict[str, Any]:
    """The real uv syft SBOM, its components repeated under distinct names until it serializes past ``size`` bytes."""
    sbom = _sbom_fixture()
    components = sbom["components"]
    copies = size // len(json.dumps(components)) + 1
    sbom["components"] = [
        {**component, "bom-ref": f"{component['bom-ref']}-{n}", "name": f"{component['name']}-{n}"}
        for n in range(copies)
        for component in components
    ]
    return sbom


async def _seed_scan(db, sbom: dict[str, Any]) -> Scan:
    """A CI run's scan whose SBOM is stored the way ingest stores it."""
    ref = await _upload_sbom_to_gridfs(AsyncIOMotorGridFSBucket(db), sbom, _SCAN_ID)
    scan = Scan(
        id=_SCAN_ID,
        project_id=_PROJECT_ID,
        pipeline_id=_PIPELINE_ID,
        commit_hash=_COMMIT,
        branch="main",
        status="completed",
        sbom_refs=[ref],
    )
    await db.scans.insert_one(scan.model_dump(by_alias=True))
    return scan


async def _seed_scan_with_result_and_callgraph(client, db, sbom: dict[str, Any]) -> None:
    await _seed_scan(db, sbom)
    await AnalysisResultRepository(db).save_result(_SCAN_ID, "kics", _KICS_REPORT)
    with patch(
        "app.api.deps._authenticate_ci",
        new_callable=AsyncMock,
        return_value=Project(id=_PROJECT_ID, name="test-project"),
    ):
        resp = await client.post(
            f"/api/v1/projects/{_PROJECT_ID}/callgraph",
            json={"format": "madge", "pipeline_id": _PIPELINE_ID, "commit_hash": _COMMIT, "data": _MADGE},
            headers={"Job-Token": "gitlab.oidc.token"},
        )
    assert resp.status_code == 200, resp.text


async def _stored_files(db) -> dict[ObjectId, tuple[str, bytes]]:
    fs = AsyncIOMotorGridFSBucket(db)
    stored = {}
    async for file in db["fs.files"].find({}, {"filename": 1}):
        stored[file["_id"]] = (file["filename"], await (await fs.open_download_stream(file["_id"])).read())
    return stored


async def _expire(db) -> None:
    """Retention deletes the archived scan; a day later the reaper deletes every file nothing references."""
    await delete_scans_and_related_data(db, [_SCAN_ID])
    await db["fs.files"].update_many({}, {"$set": {"uploadDate": datetime.now(timezone.utc) - timedelta(days=2)}})
    await reap_orphan_gridfs_files(db)


async def _archive(db) -> ArchiveMetadata:
    metadata = await archive_scan(db, _SCAN_ID)
    assert metadata is not None
    return metadata


async def _measured(call) -> tuple[Any, int]:
    tracemalloc.start()
    try:
        result = await call
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    return result, peak


async def _aiter(items: list[Any]) -> AsyncIterator[Any]:
    for item in items:
        yield item


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_a_scan_with_20_mib_sbom_result_and_callgraph_files_round_trips_byte_identical_under_the_same_ids(
    client, db, archive_env
):
    await _seed_scan_with_result_and_callgraph(client, db, _sbom_of(20 * _MIB))
    before = await _stored_files(db)
    assert len(before) == 3
    assert max(len(data) for _, data in before.values()) > _MONGO_DOCUMENT_LIMIT

    await _archive(db)
    await _expire(db)
    assert await db["fs.files"].count_documents({}) == 0
    restored = await restore_scan(db, _SCAN_ID)

    assert restored is not None
    assert ARCHIVE_GRIDFS_CHUNK_FRAME in restored.collections_restored
    assert await _stored_files(db) == before
    row = await db.analysis_results.find_one({"scan_id": _SCAN_ID})
    assert await AnalysisResultRepository(db).load_result(row) == _KICS_REPORT


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_archive_memory_stays_bounded_for_a_64_mib_sbom(db, archive_env):
    await _seed_scan(db, _sbom_of(64 * _MIB))
    before = await _stored_files(db)
    ((_, sbom),) = before.values()
    assert len(sbom) > 4 * _MONGO_DOCUMENT_LIMIT

    _, archive_peak = await _measured(_archive(db))
    await _expire(db)
    restored, restore_peak = await _measured(restore_scan(db, _SCAN_ID))

    assert restored is not None
    assert await _stored_files(db) == before
    assert archive_peak < _PEAK_BOUND, f"archive peak {archive_peak / _MIB:.1f} MiB"
    assert restore_peak < _RESTORE_PEAK_BOUND, f"restore peak {restore_peak / _MIB:.1f} MiB"


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_a_legacy_gridfs_sboms_bundle_still_restores(db, archive_env):
    file_id = ObjectId()
    sbom = _sbom_fixture()
    scan = Scan(
        id=_SCAN_ID,
        project_id=_PROJECT_ID,
        branch="main",
        status="completed",
        sbom_refs=[make_gridfs_ref(file_id, "sbom-legacy.json")],
    ).model_dump(by_alias=True)
    legacy_frame = {"gridfs_id": str(file_id), "filename": "sbom-legacy.json", "data": sbom}
    bundle = b"".join(
        [
            line
            async for line in BundleFrames.write(
                scan_doc=scan, collections={"gridfs_sboms": _aiter([legacy_frame])}, stats=BundleStats()
            )
        ]
    )
    metadata = ArchiveMetadata(
        project_id=_PROJECT_ID, scan_id=_SCAN_ID, s3_key="legacy.bundle", s3_bucket="test-bucket"
    )
    archive_env.objects[metadata.s3_key] = zlib.compress(bundle, wbits=31)
    await ArchiveMetadataRepository(db).create(metadata)

    restored = await restore_scan(db, _SCAN_ID)

    assert restored is not None
    assert await _stored_files(db) == {file_id: ("sbom-legacy.json", json.dumps(sbom).encode())}
    assert (await db.scans.find_one({"_id": _SCAN_ID}))["sbom_refs"] == scan["sbom_refs"]


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_a_rescan_shared_file_present_at_restore_is_left_untouched(db, archive_env):
    scan = await _seed_scan(db, _sbom_fixture())
    await db.scans.insert_one(build_rescan(scan.model_dump(by_alias=True)).model_dump(by_alias=True))
    await _archive(db)
    await _expire(db)
    (shared,) = await db["fs.files"].find({}).to_list(None)
    chunk_ids = await db["fs.chunks"].distinct("_id")

    restored = await restore_scan(db, _SCAN_ID)

    assert restored is not None
    assert await db["fs.files"].find({}).to_list(None) == [shared]
    assert await db["fs.chunks"].distinct("_id") == chunk_ids


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_a_restore_failing_mid_file_leaves_no_chunks_and_a_retry_succeeds(client, db, archive_env, monkeypatch):
    await _seed_scan_with_result_and_callgraph(client, db, _sbom_of(20 * _MIB))
    before = await _stored_files(db)
    await _archive(db)
    await _expire(db)
    open_bundle_stream = archive._open_bundle_stream

    async def reset_inside_the_sbom(metadata: ArchiveMetadata) -> AsyncIterator[bytes]:
        served = 0
        async for chunk in open_bundle_stream(metadata):
            if served > 10 * _MIB:
                raise ConnectionResetError("S3 connection reset by peer")
            served += len(chunk)
            yield chunk

    monkeypatch.setattr(archive, "_open_bundle_stream", reset_inside_the_sbom)
    assert await restore_scan(db, _SCAN_ID) is None
    assert await db["fs.chunks"].count_documents({}) == 0
    assert await db["fs.files"].count_documents({}) == 0
    assert await db.scans.find_one({"_id": _SCAN_ID}) is None

    monkeypatch.setattr(archive, "_open_bundle_stream", open_bundle_stream)
    assert await restore_scan(db, _SCAN_ID) is not None
    assert await _stored_files(db) == before


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_the_download_copy_keeps_chunk_frames_and_a_valid_footer(client, db, archive_env):
    await _seed_scan_with_result_and_callgraph(client, db, _sbom_of(20 * _MIB))
    before = await _stored_files(db)
    metadata = await _archive(db)

    archived = zlib.decompress(archive_env.objects[metadata.s3_key], wbits=31).splitlines(keepends=True)
    downloaded = zlib.decompress(b"".join([chunk async for chunk in stream_bundle_for_download(metadata)]), wbits=31)

    first_chunk = archived.index(json_line({"collection": ARCHIVE_GRIDFS_CHUNK_FRAME})) + 1
    assert downloaded.splitlines(keepends=True)[first_chunk:-1] == archived[first_chunk:-1]
    events = [event async for event in read_bundle_frames(_aiter([downloaded]))]
    assert events[-1]["type"] == "footer"
    copied: dict[ObjectId, tuple[str, bytearray]] = {}
    for event in events:
        if event.get("collection") == ARCHIVE_GRIDFS_CHUNK_FRAME:
            frame = event["data"]
            copied.setdefault(frame["_id"], (frame["filename"], bytearray()))[1].extend(frame["data"])
    assert copied == before
