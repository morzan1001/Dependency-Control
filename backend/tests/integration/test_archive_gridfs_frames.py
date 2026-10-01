"""An archive bundle carries every GridFS file of a scan as chunk frames, restored byte-identical under the same ids."""

import asyncio
import contextlib
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
from motor.motor_asyncio import AsyncIOMotorGridFSBucket, AsyncIOMotorGridIn
from pymongo.common import MAX_MESSAGE_SIZE
from pymongo.errors import AutoReconnect

from app.api.v1.endpoints.ingest import _upload_recognized_sboms
from app.core.constants import ARCHIVE_GRIDFS_CHUNK_FRAME
from app.models.archive import ArchiveMetadata
from app.models.project import Project, Scan
from app.repositories.analysis_results import AnalysisResultRepository
from app.repositories.archive_metadata import ArchiveMetadataRepository
from app.services import archive
from app.services.archive import archive_scan, restore_scan, stream_bundle_for_download
from app.services.archive_bundle import BundleFrames, BundleStats, json_line, read_bundle_frames
from app.services.gridfs_maintenance import reap_orphan_gridfs_files
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
    [ref] = await _upload_recognized_sboms([sbom], db, _SCAN_ID)
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


async def _delete_and_age(db, scan_ids: tuple[str, ...]) -> None:
    await delete_scans_and_related_data(db, list(scan_ids))
    await db["fs.files"].update_many({}, {"$set": {"uploadDate": datetime.now(timezone.utc) - timedelta(days=2)}})


async def _expire(db, scan_ids: tuple[str, ...] = (_SCAN_ID,)) -> None:
    """Retention deletes the archived scans; a day later the reaper deletes every file nothing references."""
    await _delete_and_age(db, scan_ids)
    await reap_orphan_gridfs_files(db)


async def _archive(db) -> ArchiveMetadata:
    metadata = await archive_scan(db, _SCAN_ID)
    assert metadata is not None
    return metadata


async def _archive_without_chunk_frames(db, archive_env, sbom: dict[str, Any]) -> None:
    """Store the bundle an archive from before chunk frames wrote: each SBOM as one parsed gridfs_sboms entry."""
    scan = await db.scans.find_one({"_id": _SCAN_ID})
    entries = [{"gridfs_id": ref["gridfs_id"], "filename": ref["filename"], "data": sbom} for ref in scan["sbom_refs"]]
    bundle = b"".join(
        [
            line
            async for line in BundleFrames.write(
                scan_doc=scan, collections={"gridfs_sboms": _aiter(entries)}, stats=BundleStats()
            )
        ]
    )
    metadata = ArchiveMetadata(
        project_id=_PROJECT_ID, scan_id=_SCAN_ID, s3_key="legacy.bundle", s3_bucket="test-bucket"
    )
    archive_env.objects[metadata.s3_key] = zlib.compress(bundle, wbits=31)
    await ArchiveMetadataRepository(db).create(metadata)


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


def _replay_with(monkeypatch, before_event) -> None:
    """Run ``before_event`` on every bundle event a restore reads, before the restore processes it."""
    read_bundle_frames = archive.read_bundle_frames

    async def intercepted(source: AsyncIterator[bytes]) -> AsyncIterator[dict[str, Any]]:
        async for event in read_bundle_frames(source):
            await before_event(event)
            yield event

    monkeypatch.setattr(archive, "read_bundle_frames", intercepted)


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
    sbom = _sbom_fixture()
    scan = await _seed_scan(db, sbom)
    before = await _stored_files(db)
    await _archive_without_chunk_frames(db, archive_env, sbom)
    await _expire(db)

    restored = await restore_scan(db, _SCAN_ID)

    assert restored is not None
    assert await _stored_files(db) == before
    assert (await db.scans.find_one({"_id": _SCAN_ID}))["sbom_refs"] == scan.sbom_refs


@pytest.mark.asyncio
@pytest.mark.live_mongo
@pytest.mark.parametrize("chunk_frames", [True, False], ids=["chunk-frames", "legacy-gridfs-sboms"])
async def test_a_rescan_shared_file_present_at_restore_is_left_untouched(db, archive_env, chunk_frames):
    sbom = _sbom_fixture()
    scan = await _seed_scan(db, sbom)
    await db.scans.insert_one(build_rescan(scan.model_dump(by_alias=True)).model_dump(by_alias=True))
    if chunk_frames:
        await _archive(db)
    else:
        await _archive_without_chunk_frames(db, archive_env, sbom)
    await _expire(db)
    (shared,) = await db["fs.files"].find({}).to_list(None)
    chunk_ids = await db["fs.chunks"].distinct("_id")

    restored = await restore_scan(db, _SCAN_ID)

    assert restored is not None
    assert await db["fs.files"].find({}).to_list(None) == [shared]
    assert await db["fs.chunks"].distinct("_id") == chunk_ids


@pytest.mark.asyncio
@pytest.mark.live_mongo
@pytest.mark.parametrize("sbom_size", [_MIB, 64 * _MIB], ids=["buffered-until-close", "flushed-mid-file"])
async def test_concurrent_restores_of_scans_sharing_an_absent_file_both_finish_with_the_file_intact(
    db, archive_env, monkeypatch, sbom_size
):
    scan = await _seed_scan(db, _sbom_of(sbom_size))
    rescan = build_rescan(scan.model_dump(by_alias=True))
    await db.scans.insert_one(rescan.model_dump(by_alias=True))
    before = await _stored_files(db)
    for scan_id in (_SCAN_ID, rescan.id):
        assert await archive_scan(db, scan_id) is not None
    await _expire(db, (_SCAN_ID, rescan.id))
    assert await db["fs.files"].count_documents({}) == 0
    both_reached_the_file = asyncio.Barrier(2)

    async def meet_at_the_first_chunk_frame(event: dict[str, Any]) -> None:
        if event.get("collection") == ARCHIVE_GRIDFS_CHUNK_FRAME and event["data"]["n"] == 0:
            await both_reached_the_file.wait()

    _replay_with(monkeypatch, meet_at_the_first_chunk_frame)
    restored = await asyncio.gather(restore_scan(db, _SCAN_ID), restore_scan(db, rescan.id))

    assert await _stored_files(db) == before
    assert None not in restored


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_a_legacy_restore_racing_a_chunk_frame_restore_of_a_shared_absent_file_leaves_it_intact(
    db, archive_env, monkeypatch
):
    sbom = _sbom_of(_MIB)
    scan = await _seed_scan(db, sbom)
    rescan = build_rescan(scan.model_dump(by_alias=True))
    await db.scans.insert_one(rescan.model_dump(by_alias=True))
    before = await _stored_files(db)
    assert await archive_scan(db, rescan.id) is not None
    await _archive_without_chunk_frames(db, archive_env, sbom)
    await _expire(db, (_SCAN_ID, rescan.id))
    monkeypatch.setattr(archive, "_GRIDFS_RESTORE_LOCK_POLL_SECONDS", 0.01)
    rescan_is_mid_file = asyncio.Event()
    legacy_restore_done = asyncio.Event()

    async def keep_the_rescan_mid_file_while_the_legacy_restore_runs(event: dict[str, Any]) -> None:
        if event["type"] == "header" and event["data"]["scan"]["_id"] == _SCAN_ID:
            await rescan_is_mid_file.wait()
        elif event.get("collection") == ARCHIVE_GRIDFS_CHUNK_FRAME and event["data"]["n"] == 1:
            rescan_is_mid_file.set()
            # The legacy restore cannot finish while the rescan's restore holds the file, so the wait may time out.
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(legacy_restore_done.wait(), timeout=1)

    async def restore_legacy() -> Any:
        try:
            return await restore_scan(db, _SCAN_ID)
        finally:
            legacy_restore_done.set()

    _replay_with(monkeypatch, keep_the_rescan_mid_file_while_the_legacy_restore_runs)
    restored = await asyncio.gather(restore_scan(db, rescan.id), restore_legacy())

    assert await _stored_files(db) == before
    assert None not in restored


async def _write_again_after_the_renewal_is_due() -> None:
    await asyncio.sleep(0.2)


async def _fail_before_writing_again() -> None:
    raise ConnectionResetError("S3 connection reset by peer")


@pytest.mark.asyncio
@pytest.mark.live_mongo
@pytest.mark.parametrize(
    "resume", [_write_again_after_the_renewal_is_due, _fail_before_writing_again], ids=["writes", "fails"]
)
async def test_a_restore_that_lost_its_file_lock_fails_and_leaves_the_new_holders_chunks(
    db, archive_env, monkeypatch, resume
):
    await _seed_scan(db, _sbom_of(_MIB))
    await _archive(db)
    await _expire(db)
    monkeypatch.setattr(archive, "_ARCHIVE_LOCK_TTL_SECONDS", 0.3)
    peer_chunk = {"n": 999, "data": b"written by the restore that took the file over"}

    async def take_the_file_over_after_its_first_chunk(event: dict[str, Any]) -> None:
        if event.get("collection") == ARCHIVE_GRIDFS_CHUNK_FRAME and event["data"]["n"] == 1:
            file_id = event["data"]["_id"]
            await db.distributed_locks.update_one({"_id": f"restore-gridfs:{file_id}"}, {"$set": {"holder": "peer"}})
            await db["fs.chunks"].insert_one({"files_id": file_id, **peer_chunk})
            await resume()

    _replay_with(monkeypatch, take_the_file_over_after_its_first_chunk)

    assert await restore_scan(db, _SCAN_ID) is None
    assert await db["fs.chunks"].find({}, {"_id": 0, "files_id": 0}).to_list(None) == [peer_chunk]


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_a_restore_whose_abort_fails_still_releases_its_file_lock(db, archive_env, monkeypatch):
    await _seed_scan(db, _sbom_of(_MIB))
    await _archive(db)
    await _expire(db)

    async def fail_mid_file(event: dict[str, Any]) -> None:
        if event.get("collection") == ARCHIVE_GRIDFS_CHUNK_FRAME and event["data"]["n"] == 1:
            await _fail_before_writing_again()

    _replay_with(monkeypatch, fail_mid_file)
    monkeypatch.setattr(AsyncIOMotorGridIn, "abort", AsyncMock(side_effect=AutoReconnect("primary stepped down")))

    assert await restore_scan(db, _SCAN_ID) is None
    assert await db.distributed_locks.find({}).to_list(None) == []


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_a_reaper_run_whenever_a_restore_reaches_a_file_frees_none_of_the_files_it_skips_as_present(
    client, db, archive_env, monkeypatch
):
    await _seed_scan_with_result_and_callgraph(client, db, _sbom_fixture())
    before = await _stored_files(db)
    await _archive(db)
    # Retention deleted the scan, but the reaper has not yet freed the files nothing references now.
    await _delete_and_age(db, (_SCAN_ID,))
    reaped: list[int] = []
    write = archive._GridFSRestore.write

    async def reap_then_write(self, frame: dict[str, Any]) -> None:
        reaped.append(await reap_orphan_gridfs_files(db))
        await write(self, frame)

    monkeypatch.setattr(archive._GridFSRestore, "write", reap_then_write)
    restored = await restore_scan(db, _SCAN_ID)

    assert restored is not None
    assert reaped and not any(reaped)
    assert await _stored_files(db) == before


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_a_restore_failing_mid_file_leaves_no_chunks_and_a_retry_succeeds(client, db, archive_env, monkeypatch):
    await _seed_scan_with_result_and_callgraph(client, db, _sbom_of(64 * _MIB))
    before = await _stored_files(db)
    await _archive(db)
    await _expire(db)
    open_bundle_stream = archive._open_bundle_stream

    async def reset_once_chunks_are_stored(metadata: ArchiveMetadata) -> AsyncIterator[bytes]:
        async for chunk in open_bundle_stream(metadata):
            if await db["fs.chunks"].count_documents({}):
                raise ConnectionResetError("S3 connection reset by peer")
            yield chunk

    monkeypatch.setattr(archive, "_open_bundle_stream", reset_once_chunks_are_stored)
    assert await restore_scan(db, _SCAN_ID) is None
    assert await db["fs.chunks"].count_documents({}) == 0
    assert await db["fs.files"].count_documents({}) == 0
    assert await db.scans.find_one({"_id": _SCAN_ID}) is None

    monkeypatch.setattr(archive, "_open_bundle_stream", open_bundle_stream)
    assert await restore_scan(db, _SCAN_ID) is not None
    assert await _stored_files(db) == before


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_a_retry_clears_the_chunks_a_restore_killed_mid_file_left_behind(db, archive_env):
    await _seed_scan(db, _sbom_of(_MIB))
    before = await _stored_files(db)
    ((sbom_id, _),) = before.items()
    stray = await db["fs.chunks"].find({"files_id": sbom_id, "n": {"$lt": 2}}).to_list(None)
    await _archive(db)
    await _expire(db)
    # A killed pod never runs the GridIn abort, so its chunks outlive it without a files document.
    await db["fs.chunks"].insert_many(stray)

    restored = await restore_scan(db, _SCAN_ID)

    assert restored is not None
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
