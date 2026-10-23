import asyncio
import contextlib
import json
import logging
import re
import time
import zlib
from collections.abc import AsyncIterator, Awaitable, Callable
from datetime import datetime, timedelta, timezone
from functools import partial
from typing import Any

from bson import Binary, ObjectId
from cryptography.exceptions import InvalidTag
from gridfs.errors import FileExists, NoFile
from motor.motor_asyncio import AsyncIOMotorDatabase, AsyncIOMotorGridFSBucket, AsyncIOMotorGridIn
from pymongo.errors import DuplicateKeyError, PyMongoError

from app.core import abatched
from app.core.config import settings
from app.core.constants import (
    ARCHIVE_BATCH_SIZE,
    ARCHIVE_GRIDFS_CHUNK_FRAME,
    ARCHIVE_GRIDFS_FRAME,
    ARCHIVE_KEY_PATTERN,
    ARCHIVE_PATH_TEMPLATE,
    ARCHIVE_RESTORE_LOCK_TEMPLATE,
    ENCRYPTION_MAGIC,
    ORPHAN_MIN_AGE_HOURS,
    REACHABILITY_LOCK_TEMPLATE,
    RESTORE_INSERT_BATCH_SIZE,
    RETENTION_PROTECTED_FLAG_VALUES,
    SCAN_ACTIVE_STATUSES,
    SCAN_SCOPED_COLLECTIONS,
)
from app.core.encryption import decrypt_stream, encrypt_stream, is_encryption_enabled
from app.core.log_utils import sanitize_for_log
from app.core.metrics import (
    ArchiveFailureReason,
    archive_bundle_compressed_bytes,
    archive_housekeeping_scans_processed_total,
    archive_operation_duration_seconds,
    archive_operations_total,
    archive_orphan_objects_reaped_total,
    count_archive_failure,
)
from app.core.s3 import (
    archive_key_prefix,
    delete_object,
    download_stream,
    is_archive_enabled,
    list_objects,
    upload_stream,
)
from app.models.archive import ArchiveMetadata
from app.repositories.archive_metadata import ArchiveMetadataRepository
from app.repositories.distributed_locks import (
    LOCK_RENEWALS_PER_TTL,
    DistributedLocksRepository,
    LockLost,
    new_lock_holder,
    run_holding_lock,
)
from app.repositories.scans import RESTORED_SCAN_MATCH
from app.schemas.archive import ArchiveRestoreResponse
from app.schemas.trufflehog import TruffleHogFinding
from app.services.analyzers.license_compliance.normalizer import BUNDLE_LICENSE_PARAMETER, strip_license_parameters
from app.services.archive_bundle import (
    BundleFrames,
    BundleStats,
    BundleVersionError,
    json_line,
    load_json_line,
    read_bundle_frames,
    rewrite_bundle_frames,
)
from app.services.gridfs_maintenance import (
    GRIDFS_RESTORE_LOCK_TEMPLATE,
    extract_gridfs_ids_from_refs,
    iter_gridfs_chunks,
)
from app.services.releases import release_protected_scan_ids
from app.services.sbom_parser import strip_license_header
from app.services.update_frequency_rollup import record_scan_update_delta

logger = logging.getLogger(__name__)

_ARCHIVE_LOCK_TTL_SECONDS = 600
_GRIDFS_RESTORE_LOCK_POLL_SECONDS = 1
# zlib releases the GIL, so a chunk this large (a whole SBOM line) compresses in a thread instead of stalling the loop.
_COMPRESS_IN_THREAD_MIN_BYTES = 1 << 20
_DECOMPRESS_PIECE_BYTES = 1 << 20

# Marker names are attacker-influenceable (the footer is a plain sha256, not an HMAC), so others abort the restore.
_RESTORABLE_COLLECTIONS = frozenset({*SCAN_SCOPED_COLLECTIONS, ARCHIVE_GRIDFS_FRAME, ARCHIVE_GRIDFS_CHUNK_FRAME})


class _ArchiveSourceReadError(Exception):
    """A source read failed; counted as INTEGRITY, not S3_ERROR."""


class RestoreFailed(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def _restore_failed(reason: str) -> RestoreFailed:
    count_archive_failure("restore", reason)
    return RestoreFailed(reason)


def _hash_plaintext_secrets(collection: str, doc: dict[str, Any]) -> None:
    """Legacy rows and bundles can hold TruffleHog's plaintext Raw; only its digest prefix may leave them."""
    if collection != "analysis_results" or doc.get("analyzer_name") != "trufflehog":
        return
    findings = (doc.get("result") or {}).get("findings")
    if findings:
        doc["result"]["findings"] = [TruffleHogFinding.model_validate(f).model_dump() for f in findings]


def _strip_license_parameters(collection: str, doc: dict[str, Any]) -> None:
    """Bundles archived before ingest stripped Bundle-License parameters still carry them."""
    if collection != "dependencies":
        return
    if ";" in (doc.get("license") or ""):
        doc["license"], url = strip_license_header(doc["license"], doc.get("purl"))
        doc["license_url"] = doc.get("license_url") or url
    # A header that named its licence by URL left its parameters on that URL.
    if BUNDLE_LICENSE_PARAMETER.search(doc.get("license_url") or ""):
        doc["license_url"] = strip_license_parameters(doc["license_url"])[0]


async def _hash_plaintext_secrets_in(
    collection: str, docs: AsyncIterator[dict[str, Any]]
) -> AsyncIterator[dict[str, Any]]:
    try:
        async for doc in docs:
            _hash_plaintext_secrets(collection, doc)
            yield doc
    except PyMongoError as e:
        raise _ArchiveSourceReadError(str(e)) from e


async def _stream_gridfs_chunks(db: Any, scan_doc: dict[str, Any]) -> AsyncIterator[dict[str, Any]]:
    """Each file opens with an n=0 frame, even when empty."""
    scan_id = scan_doc["_id"]
    try:
        file_ids = dict.fromkeys(
            [
                *extract_gridfs_ids_from_refs(scan_doc.get("sbom_refs", [])),
                *await db.analysis_results.distinct("result_gridfs_id", {"scan_id": scan_id}),
                *await db.callgraphs.distinct("graph_gridfs_id", {"scan_id": scan_id}),
            ]
        )
    except PyMongoError as e:
        raise _ArchiveSourceReadError(str(e)) from e
    for gid in file_ids:
        try:
            file_id = ObjectId(gid)
            stream = await AsyncIOMotorGridFSBucket(db).open_download_stream(file_id)
            n = 0
            async for chunk in iter_gridfs_chunks(stream):
                yield {"_id": file_id, "n": n, "filename": stream.filename, "data": Binary(chunk)}
                n += 1
            if n == 0:
                yield {"_id": file_id, "n": 0, "filename": stream.filename, "data": Binary(b"")}
        except NoFile:
            # Gone for good, so the bundle loses nothing; aborting would keep retention from the scan forever.
            logger.warning(
                "GridFS file %s of scan %s is already gone, archiving the scan without it",
                sanitize_for_log(gid),
                sanitize_for_log(scan_id),
            )
        except Exception as e:
            # Re-raised: a skipped file would archive as success and housekeeping would then delete the only copy.
            logger.error(
                "Failed to load GridFS file %s of scan %s, aborting its archive to avoid data loss: %s",
                sanitize_for_log(gid),
                sanitize_for_log(scan_id),
                sanitize_for_log(e),
            )
            raise _ArchiveSourceReadError(str(e)) from e


async def _gzip_compress_stream(source: AsyncIterator[bytes]) -> AsyncIterator[bytes]:
    compressor = zlib.compressobj(level=6, wbits=31)
    async for chunk in source:
        if not chunk:
            continue
        if len(chunk) >= _COMPRESS_IN_THREAD_MIN_BYTES:
            out = await asyncio.to_thread(compressor.compress, chunk)
        else:
            out = compressor.compress(chunk)
        if out:
            yield out
    tail = compressor.flush(zlib.Z_FINISH)
    if tail:
        yield tail


async def _gzip_decompress_stream(source: AsyncIterator[bytes]) -> AsyncIterator[bytes]:
    decompressor = zlib.decompressobj(wbits=31)
    async for chunk in source:
        data = chunk
        # A highly compressed chunk would otherwise inflate in one piece many times its size.
        while data:
            out = decompressor.decompress(data, _DECOMPRESS_PIECE_BYTES)
            if out:
                yield out
            data = decompressor.unconsumed_tail
    tail = decompressor.flush()
    if tail:
        yield tail


def _build_archive_payload(
    db: Any,
    scan_doc: dict[str, Any],
    scan_id: str,
    stats: BundleStats,
    archived_at: datetime,
) -> tuple[AsyncIterator[bytes], str]:
    frames = BundleFrames.write(
        scan_doc=scan_doc,
        collections={
            **{
                name: _hash_plaintext_secrets_in(name, getattr(db, name).find({"scan_id": scan_id}).batch_size(500))
                for name in SCAN_SCOPED_COLLECTIONS
            },
            ARCHIVE_GRIDFS_CHUNK_FRAME: _stream_gridfs_chunks(db, scan_doc),
        },
        stats=stats,
        archived_at=archived_at,
    )
    gzipped = _gzip_compress_stream(frames)
    if is_encryption_enabled():
        return encrypt_stream(gzipped), "application/octet-stream"
    return gzipped, "application/gzip"


async def _drop_upload(s3_key: str, reason: str) -> None:
    try:
        await delete_object(s3_key)
    except Exception:
        logger.exception("Cleanup delete of the dropped S3 upload %s failed", sanitize_for_log(s3_key))
    count_archive_failure("archive", reason)


async def _save_archive_metadata(
    repo: ArchiveMetadataRepository,
    scan_doc: dict[str, Any],
    scan_id: str,
    s3_key: str,
    total: int,
    stats: BundleStats,
    archived_at: datetime,
) -> ArchiveMetadata | None:
    sbom_filenames = [
        ref["filename"] for ref in scan_doc.get("sbom_refs", []) if isinstance(ref, dict) and ref.get("filename")
    ]
    metadata = ArchiveMetadata(
        project_id=scan_doc["project_id"],
        scan_id=scan_id,
        s3_key=s3_key,
        s3_bucket=settings.S3_BUCKET_NAME,
        branch=scan_doc.get("branch"),
        commit_hash=scan_doc.get("commit_hash"),
        scan_created_at=scan_doc.get("created_at"),
        compressed_size_bytes=total,
        findings_count=stats.findings,
        critical_findings_count=stats.critical_findings,
        high_findings_count=stats.high_findings,
        dependencies_count=stats.dependencies,
        sbom_filenames=sbom_filenames,
        archived_at=archived_at,
    )
    try:
        await repo.create(metadata)
        return metadata
    except DuplicateKeyError as e:
        # Another worker won the metadata insert; its upload is authoritative, clean up ours.
        logger.info(
            "Lost the archive race for scan %s, cleaning up our S3 orphan: %s",
            sanitize_for_log(scan_id),
            sanitize_for_log(e),
        )
        await _drop_upload(s3_key, ArchiveFailureReason.ALREADY_EXISTS)
        return None
    except Exception as e:
        # The insert may still have landed, so the upload stays; the orphan reaper takes it if nothing points at it.
        logger.warning("Metadata create failed for scan %s: %s", sanitize_for_log(scan_id), sanitize_for_log(e))
        count_archive_failure("archive", ArchiveFailureReason.UNKNOWN)
        return None


async def _load_scan_for_archive(
    db: Any,
    repo: ArchiveMetadataRepository,
    scan_id: str,
) -> tuple[ArchiveMetadata | None, dict[str, Any] | None]:
    """Exactly one is non-None on the happy path; both None means nothing to archive."""
    existing = await repo.find_by_scan_id(scan_id)
    scan_doc = await db.scans.find_one({"_id": scan_id})
    if not scan_doc:
        if existing:
            logger.info("Scan %s already archived, returning existing metadata", sanitize_for_log(scan_id))
            return existing, None
        logger.error("Scan %s not found for archiving", sanitize_for_log(scan_id))
        count_archive_failure("archive", ArchiveFailureReason.NOT_FOUND)
        return None, None
    # Checked after the scan read: a reachability pass locking later claims later, so the bundle keeps its flag.
    if (
        scan_doc.get("pinned") in RETENTION_PROTECTED_FLAG_VALUES
        or scan_doc.get("status") in SCAN_ACTIVE_STATUSES
        or await DistributedLocksRepository(db).held_locks([REACHABILITY_LOCK_TEMPLATE.format(scan_id=scan_id)])
        or await db.scans.find_one({"is_rescan": True, "original_scan_id": scan_id}, {"_id": 1})
    ):
        logger.info("Scan %s pinned, under analysis or rescanned, not archiving it", sanitize_for_log(scan_id))
        count_archive_failure("archive", ArchiveFailureReason.PROTECTED)
        return None, None
    if existing is None:
        return None, scan_doc
    # A restore since the archive leaves metadata the stale-metadata reaper may delete at any moment.
    if all(scan_doc[field] <= existing.archived_at for field in ("updated_at", "restored_at") if scan_doc.get(field)):
        return existing, None
    # Its bundle lacks what ingest wrote since, and a recreated scan lacks what only the bundle holds.
    logger.warning("Scan %s written to or restored since it was archived, keeping both", sanitize_for_log(scan_id))
    count_archive_failure("archive", ArchiveFailureReason.WRITTEN_SINCE_ARCHIVE)
    return None, None


async def _upload_archive_bundle(
    db: Any,
    scan_doc: dict[str, Any],
    scan_id: str,
    s3_key: str,
    archived_at: datetime,
) -> tuple[int, BundleStats] | None:
    stats = BundleStats()
    payload, content_type = _build_archive_payload(db, scan_doc, scan_id, stats, archived_at)
    try:
        total = await upload_stream(s3_key, payload, content_type=content_type)
    except _ArchiveSourceReadError as e:
        logger.error(
            "Aborting the archive of scan %s: source data could not be read intact: %s",
            sanitize_for_log(scan_id),
            sanitize_for_log(e),
        )
        count_archive_failure("archive", ArchiveFailureReason.INTEGRITY)
        return None
    except Exception as e:
        logger.exception("Failed to upload the archive of scan %s: %s", sanitize_for_log(scan_id), sanitize_for_log(e))
        count_archive_failure("archive", ArchiveFailureReason.S3_ERROR)
        return None
    archive_bundle_compressed_bytes.observe(total)
    return total, stats


async def archive_scan(
    db: AsyncIOMotorDatabase,
    scan_id: str,
) -> ArchiveMetadata | None:
    repo = ArchiveMetadataRepository(db)
    lock_repo = DistributedLocksRepository(db)
    lock_name = f"archive:{scan_id}"
    holder = new_lock_holder()

    if not await lock_repo.acquire_lock(lock_name, holder, ttl_seconds=_ARCHIVE_LOCK_TTL_SECONDS):
        logger.info("Archive of scan %s skipped, lock held by another worker", sanitize_for_log(scan_id))
        count_archive_failure("archive", ArchiveFailureReason.LOCK_HELD)
        return None

    try:
        # Taken before the scan is read, so any ingest the bundle may have missed is dated after it.
        archived_at = datetime.now(timezone.utc)
        existing, scan_doc = await _load_scan_for_archive(db, repo, scan_id)
        if existing is not None:
            archive_operations_total.labels(operation="archive", status="skipped").inc()
            return existing
        if scan_doc is None:
            return None

        # Archival removes the scan document, which would orphan release resolution.
        if await release_protected_scan_ids(db, [scan_id]):
            logger.info("Archive of release scan %s refused", sanitize_for_log(scan_id))
            count_archive_failure("archive", ArchiveFailureReason.RELEASE_PROTECTED)
            return None

        project_id = scan_doc["project_id"]
        archived_at_unix = int(archived_at.timestamp())
        s3_key = archive_key_prefix() + ARCHIVE_PATH_TEMPLATE.format(
            project_id=project_id, scan_id=scan_id, archived_at_unix=archived_at_unix
        )

        renew_lock = partial(lock_repo.renew_lock, lock_name, holder, _ARCHIVE_LOCK_TTL_SECONDS)
        start_time = time.monotonic()
        try:
            upload = _upload_archive_bundle(db, scan_doc, scan_id, s3_key, archived_at)
            upload_result = await run_holding_lock(renew_lock, _ARCHIVE_LOCK_TTL_SECONDS, upload)
            # A pod that took the lock over archives on its own, possibly while this archive's delete runs.
            if upload_result is not None and not await renew_lock():
                raise LockLost
        except LockLost:
            logger.error(
                "Archive of scan %s lost its lock to another worker, dropping its upload", sanitize_for_log(scan_id)
            )
            await _drop_upload(s3_key, ArchiveFailureReason.LOCK_HELD)
            return None
        except PyMongoError:
            logger.exception(
                "Archive of scan %s could not confirm its lock, dropping its upload", sanitize_for_log(scan_id)
            )
            await _drop_upload(s3_key, ArchiveFailureReason.UNKNOWN)
            return None
        if upload_result is None:
            return None
        total, stats = upload_result

        metadata = await _save_archive_metadata(repo, scan_doc, scan_id, s3_key, total, stats, archived_at)
        if metadata is None:
            return None

        duration = time.monotonic() - start_time
        archive_operations_total.labels(operation="archive", status="success").inc()
        archive_operation_duration_seconds.labels(operation="archive").observe(duration)
        logger.info(
            "archive.success scan_id=%s project_id=%s s3_key=%s compressed_bytes=%d findings=%d dependencies=%d",
            sanitize_for_log(scan_id),
            sanitize_for_log(project_id),
            sanitize_for_log(s3_key),
            total,
            stats.findings,
            stats.dependencies,
        )
        return metadata
    except Exception:
        count_archive_failure("archive", ArchiveFailureReason.UNKNOWN)
        raise
    finally:
        await lock_repo.release_lock(lock_name, holder)


async def _open_bundle_stream(metadata: ArchiveMetadata) -> AsyncIterator[bytes]:
    """Encryption is sniffed from the ENCRYPTION_MAGIC prefix: a bundle keeps the config of its archive time."""
    s3_chunks = download_stream(metadata.s3_key, bucket=metadata.s3_bucket)

    head = bytearray()
    async for chunk in s3_chunks:
        if not chunk:
            continue
        head.extend(chunk)
        if len(head) >= len(ENCRYPTION_MAGIC):
            break

    prefix = bytes(head)

    async def _prepended() -> AsyncIterator[bytes]:
        if prefix:
            yield prefix
        async for chunk in s3_chunks:
            yield chunk

    source: AsyncIterator[bytes] = _prepended()
    decrypted = decrypt_stream(source) if prefix.startswith(ENCRYPTION_MAGIC) else source
    async for out in _gzip_decompress_stream(decrypted):
        yield out


def _hash_plaintext_secrets_in_line(collection: str, line: bytes) -> bytes:
    # json_util never escapes ASCII, so every serialized trufflehog result spells out its analyzer name.
    if collection != "analysis_results" or b"trufflehog" not in line:
        return line
    doc = load_json_line(line)
    _hash_plaintext_secrets(collection, doc)
    return json_line(doc)


def stream_bundle_for_download(metadata: ArchiveMetadata) -> AsyncIterator[bytes]:
    return _gzip_compress_stream(rewrite_bundle_frames(_open_bundle_stream(metadata), _hash_plaintext_secrets_in_line))


async def _flush_batches(
    db: Any,
    batch_by_collection: dict[str, list[dict[str, Any]]],
    collections_restored: list[str],
) -> None:
    for coll_name, docs in batch_by_collection.items():
        await getattr(db, coll_name).insert_many(docs, ordered=False)
        if coll_name not in collections_restored:
            collections_restored.append(coll_name)
    batch_by_collection.clear()


async def _handle_header_event(db: Any, data: dict[str, Any]) -> None:
    """read_bundle_frames already rejected a header of another version."""
    scan_data = data["scan"]
    scan_data["pinned"] = True
    # A re-archived scan's bundle carries its old restored_at, the reaper's restore evidence, and a cut cascade's mark.
    scan_data.pop("restored_at", None)
    scan_data.pop("retention_deleting", None)
    scan_data["restore_in_progress"] = True
    await db.scans.insert_one(scan_data)


async def _handle_doc_event(
    db: Any,
    event: dict[str, Any],
    batch_by_collection: dict[str, list[dict[str, Any]]],
    collections_restored: list[str],
) -> None:
    coll = event["collection"]
    doc = event["data"]
    _hash_plaintext_secrets(coll, doc)
    _strip_license_parameters(coll, doc)
    batch_by_collection.setdefault(coll, []).append(doc)
    # A legacy analysis_results row inlines a whole scanner report, so a batch of them has no memory bound.
    if coll == "analysis_results" or len(batch_by_collection[coll]) >= RESTORE_INSERT_BATCH_SIZE:
        await _flush_batches(db, batch_by_collection, collections_restored)


class _GridFSRestore:
    def __init__(self, db: Any) -> None:
        self._db = db
        self._locks = DistributedLocksRepository(db)
        self._holder = new_lock_holder()
        self._lock_name: str | None = None
        self._grid_in: AsyncIOMotorGridIn | None = None
        self._renew_at = 0.0

    async def write(self, frame: dict[str, Any]) -> None:
        if frame["n"] == 0:
            await self.close()
            await self._open(frame["_id"], frame["filename"])
        if self._grid_in is not None:
            if time.monotonic() >= self._renew_at:
                await self._renew()
            await self._grid_in.write(frame["data"])

    async def close(self) -> None:
        if self._grid_in is not None:
            await self._renew()
            await self._grid_in.close()
            self._grid_in = None
        await self._release()

    async def abort(self) -> None:
        try:
            if self._grid_in is not None:
                await self._renew()
                await self._grid_in.abort()
        finally:
            self._grid_in = None
            await self._release()

    async def _open(self, file_id: ObjectId, filename: str) -> None:
        self._lock_name = GRIDFS_RESTORE_LOCK_TEMPLATE.format(file_id=file_id)
        # A peer on another pod may hold it, so no in-process event can announce the release.
        while not await self._locks.acquire_lock(self._lock_name, self._holder, _ARCHIVE_LOCK_TTL_SECONDS):  # noqa: ASYNC110
            await asyncio.sleep(_GRIDFS_RESTORE_LOCK_POLL_SECONDS)
        # Stored files never change; one present is live, shared with a rescan or stored by a concurrent restore.
        if await self._db["fs.files"].find_one({"_id": file_id}, {"_id": 1}):
            await self._release()
            return
        fs = AsyncIOMotorGridFSBucket(self._db)
        # Clears the chunks of a restore that died mid-file, then raises NoFile for the missing files document.
        with contextlib.suppress(NoFile):
            await fs.delete(file_id)
        self._grid_in = fs.open_upload_stream_with_id(file_id, filename)

    async def _renew(self) -> None:
        assert self._lock_name is not None
        if not await self._locks.renew_lock(self._lock_name, self._holder, _ARCHIVE_LOCK_TTL_SECONDS):
            # The restore that took the lock over owns the file now, so aborting would delete its chunks.
            self._grid_in = None
            raise FileExists(f"Another restore took over {self._lock_name}")
        self._renew_at = time.monotonic() + _ARCHIVE_LOCK_TTL_SECONDS / LOCK_RENEWALS_PER_TTL

    async def _release(self) -> None:
        if self._lock_name is not None:
            await self._locks.release_lock(self._lock_name, self._holder)
            self._lock_name = None


def _whole_file_frame(entry: dict[str, Any]) -> dict[str, Any]:
    return {
        "_id": ObjectId(entry["gridfs_id"]),
        "filename": entry["filename"],
        "n": 0,
        "data": json.dumps(entry["data"]).encode(),
    }


def bundle_failure_reason(e: Exception) -> str:
    if isinstance(e, BundleVersionError):
        return ArchiveFailureReason.VERSION_MISMATCH
    if isinstance(e, ValueError | zlib.error):
        return ArchiveFailureReason.INTEGRITY
    # Only the header insert raises it: an ingest created the scan since the restore checked for it.
    if isinstance(e, DuplicateKeyError):
        return ArchiveFailureReason.ALREADY_EXISTS
    if isinstance(e, PyMongoError):
        return ArchiveFailureReason.UNKNOWN
    if isinstance(e, InvalidTag):
        return ArchiveFailureReason.ENCRYPTION
    return ArchiveFailureReason.S3_ERROR


def _require_owner(kind: str, row_scan_id: Any, row_project_id: Any, scan_id: str, project_id: str) -> None:
    # The footer is a plain sha256, so a swapped bundle must not write what the scan_id rollback cannot remove.
    if (row_scan_id, row_project_id) != (scan_id, project_id):
        raise ValueError(f"Bundle {kind} belongs to scan {row_scan_id!r} of project {row_project_id!r}")


async def _replay_bundle(
    db: Any,
    scan_id: str,
    project_id: str,
    decompressed: AsyncIterator[bytes],
) -> tuple[str | None, list[str]]:
    collections_restored: list[str] = []
    batch_by_collection: dict[str, list[dict[str, Any]]] = {}
    gridfs = _GridFSRestore(db)

    try:
        async for event in read_bundle_frames(decompressed):
            etype = event["type"]
            if etype == "header":
                scan = event["data"].get("scan") or {}
                _require_owner("header", scan.get("_id"), scan.get("project_id"), scan_id, project_id)
                await _handle_header_event(db, event["data"])
                collections_restored.append("scans")
            elif etype == "doc":
                coll = event["collection"]
                if coll not in _RESTORABLE_COLLECTIONS:
                    raise ValueError(f"Unexpected collection in bundle: {sanitize_for_log(coll)}")
                if coll in (ARCHIVE_GRIDFS_CHUNK_FRAME, ARCHIVE_GRIDFS_FRAME):
                    # A file skipped as already stored is unreferenced, and so reapable, until its rows are in.
                    await _flush_batches(db, batch_by_collection, collections_restored)
                    await gridfs.write(
                        event["data"] if coll == ARCHIVE_GRIDFS_CHUNK_FRAME else _whole_file_frame(event["data"])
                    )
                    if coll not in collections_restored:
                        collections_restored.append(coll)
                else:
                    doc = event["data"]
                    _require_owner(coll, doc.get("scan_id"), doc.get("project_id", project_id), scan_id, project_id)
                    await _handle_doc_event(db, event, batch_by_collection, collections_restored)
            elif etype == "footer":
                await gridfs.close()
                await _flush_batches(db, batch_by_collection, collections_restored)
                break
    except Exception as e:
        reason = bundle_failure_reason(e)
        logger.exception("Restore of scan %s failed (%s): %s", sanitize_for_log(scan_id), reason, sanitize_for_log(e))
        return reason, collections_restored
    finally:
        with contextlib.suppress(PyMongoError):
            await gridfs.abort()

    return None, collections_restored


async def _rollback_partial_restore(db: Any, scan_id: str) -> None:
    """The scan doc goes last so a failed cleanup stays marked restore_in_progress for the next restore."""
    try:
        for coll in SCAN_SCOPED_COLLECTIONS:
            await getattr(db, coll).delete_many({"scan_id": scan_id})
        await db.scans.delete_one({"_id": scan_id})
    except Exception as e:
        logger.warning("Partial-restore rollback of scan %s failed: %s", sanitize_for_log(scan_id), sanitize_for_log(e))


async def roll_back_dead_restore(db: Any, scan_id: str) -> bool:
    """False while a restore holds the scan's lock; otherwise rolls back what a dead restore left flagged."""
    lock_repo = DistributedLocksRepository(db)
    lock_name = ARCHIVE_RESTORE_LOCK_TEMPLATE.format(scan_id=scan_id)
    holder = new_lock_holder()
    if not await lock_repo.acquire_lock(lock_name, holder, ttl_seconds=_ARCHIVE_LOCK_TTL_SECONDS):
        return False
    try:
        if await db.scans.find_one({"_id": scan_id, "restore_in_progress": True}, {"_id": 1}):
            logger.warning("Rolling back the leftover of a dead restore of scan %s", sanitize_for_log(scan_id))
            await _rollback_partial_restore(db, scan_id)
    finally:
        await lock_repo.release_lock(lock_name, holder)
    return True


async def _load_restore_metadata(
    db: Any,
    repo: ArchiveMetadataRepository,
    scan_id: str,
) -> ArchiveMetadata:
    # Checked first: a restore that finished while this one waited for the lock has removed the metadata.
    existing = await db.scans.find_one({"_id": scan_id}, {"restore_in_progress": 1})
    if existing and not existing.get("restore_in_progress"):
        logger.warning("Scan %s already exists in MongoDB, aborting its restore", sanitize_for_log(scan_id))
        raise _restore_failed(ArchiveFailureReason.ALREADY_EXISTS)

    metadata = await repo.find_by_scan_id(scan_id)
    if not metadata:
        logger.error("No archive metadata for scan %s", sanitize_for_log(scan_id))
        raise _restore_failed(ArchiveFailureReason.NOT_FOUND)

    if existing:
        # A running restore keeps renewing its lock, so while we hold it nobody still writes this leftover.
        logger.warning(
            "Rolling back an unfinished restore of scan %s before restoring it again", sanitize_for_log(scan_id)
        )
        await _rollback_partial_restore(db, scan_id)
    return metadata


async def _finalize_restore_cleanup(
    repo: ArchiveMetadataRepository,
    metadata: ArchiveMetadata,
    scan_id: str,
) -> None:
    """Metadata first, so none points at a deleted bundle; reapers retry failures."""
    try:
        await repo.delete_by_scan_id(scan_id)
    except Exception as e:
        logger.warning(
            "Metadata delete failed after the restore of scan %s; the stale-metadata reaper will retry: %s",
            sanitize_for_log(scan_id),
            sanitize_for_log(e),
        )
        return
    try:
        await delete_object(metadata.s3_key, bucket=metadata.s3_bucket)
    except Exception as e:
        logger.warning(
            "S3 delete of %s failed after the restore of scan %s; the orphan reaper will retry: %s",
            sanitize_for_log(metadata.s3_key),
            sanitize_for_log(scan_id),
            sanitize_for_log(e),
        )


async def _mark_restore_complete(
    db: Any,
    scan_id: str,
    renew_lock: Callable[[], Awaitable[bool]],
) -> str | None:
    # The heartbeat checks the lock only every TTL/3, so a takeover in between must still be caught before finalize.
    if not await renew_lock():
        raise LockLost
    completed = await db.scans.update_one(
        {"_id": scan_id, "restore_in_progress": True},
        {"$set": {"restored_at": datetime.now(timezone.utc)}, "$unset": {"restore_in_progress": ""}},
    )
    if completed.matched_count == 0:
        logger.error("Restored scan %s disappeared before the restore completed", sanitize_for_log(scan_id))
        await _rollback_partial_restore(db, scan_id)
        return ArchiveFailureReason.UNKNOWN
    return None


async def _abandon_restore(
    db: Any,
    scan_id: str,
    renew_lock: Callable[[], Awaitable[bool]],
) -> None:
    try:
        still_held = await renew_lock()
    except PyMongoError as e:
        # The leftover keeps its restore_in_progress flag, so the next restore rolls it back.
        logger.warning(
            "Restore of scan %s could not confirm it still holds its lock, leaving the rollback to the next restore: %s",
            sanitize_for_log(scan_id),
            sanitize_for_log(e),
        )
        return
    if not still_held:
        raise LockLost
    await _rollback_partial_restore(db, scan_id)


async def _run_restore_pipeline(
    db: Any,
    repo: ArchiveMetadataRepository,
    metadata: ArchiveMetadata,
    scan_id: str,
    renew_lock: Callable[[], Awaitable[bool]],
) -> ArchiveRestoreResponse:
    start_time = time.monotonic()
    decompressed = _open_bundle_stream(metadata)
    failure_reason, collections_restored = await _replay_bundle(db, scan_id, metadata.project_id, decompressed)
    if failure_reason is None:
        failure_reason = await _mark_restore_complete(db, scan_id, renew_lock)
    elif "scans" in collections_restored:
        # Before its header insert the restore wrote nothing, and a scan already there belongs to an ingest.
        await _abandon_restore(db, scan_id, renew_lock)
    if failure_reason is not None:
        raise _restore_failed(failure_reason)

    # The restored scan re-enters its branch timeline, so the rollup also re-points the successor.
    await record_scan_update_delta(db, scan_id)

    await _finalize_restore_cleanup(repo, metadata, scan_id)

    duration = time.monotonic() - start_time
    archive_operations_total.labels(operation="restore", status="success").inc()
    archive_operation_duration_seconds.labels(operation="restore").observe(duration)
    logger.info(
        "archive.restore.success scan_id=%s project_id=%s collections_restored=%s",
        sanitize_for_log(scan_id),
        sanitize_for_log(metadata.project_id),
        ",".join(collections_restored),
    )
    return ArchiveRestoreResponse(
        scan_id=scan_id,
        project_id=metadata.project_id,
        collections_restored=collections_restored,
    )


async def restore_scan(
    db: AsyncIOMotorDatabase,
    scan_id: str,
) -> ArchiveRestoreResponse:
    """Raises RestoreFailed with the reason it counted."""
    repo = ArchiveMetadataRepository(db)
    lock_repo = DistributedLocksRepository(db)
    lock_name = ARCHIVE_RESTORE_LOCK_TEMPLATE.format(scan_id=scan_id)
    holder = new_lock_holder()
    renew_lock = partial(lock_repo.renew_lock, lock_name, holder, _ARCHIVE_LOCK_TTL_SECONDS)

    if not await lock_repo.acquire_lock(lock_name, holder, ttl_seconds=_ARCHIVE_LOCK_TTL_SECONDS):
        logger.info("Restore of scan %s blocked, lock held", sanitize_for_log(scan_id))
        raise _restore_failed(ArchiveFailureReason.LOCK_HELD)

    try:
        metadata = await _load_restore_metadata(db, repo, scan_id)
        pipeline = _run_restore_pipeline(db, repo, metadata, scan_id, renew_lock)
        return await run_holding_lock(renew_lock, _ARCHIVE_LOCK_TTL_SECONDS, pipeline)
    except LockLost:
        logger.error("Restore of scan %s lost its lock to another restore, aborting", sanitize_for_log(scan_id))
        raise _restore_failed(ArchiveFailureReason.LOCK_HELD) from None
    finally:
        await lock_repo.release_lock(lock_name, holder)


async def reap_stale_metadata(db: Any, batch_size: int = ARCHIVE_BATCH_SIZE) -> int:
    """Drops the metadata of scans restored since archiving, which leaves their S3 object to the orphan reaper."""
    lock_repo = DistributedLocksRepository(db)

    async def _reap_batch(scans: list[dict[str, Any]]) -> int:
        restored_at_by_scan = {scan["_id"]: scan["restored_at"] for scan in scans}
        restored = [
            meta
            async for meta in db.archive_metadata.find(
                {"scan_id": {"$in": list(restored_at_by_scan)}}, {"_id": 1, "scan_id": 1, "archived_at": 1}
            )
            if restored_at_by_scan[meta["scan_id"]] > meta["archived_at"]
        ]
        if not restored:
            return 0
        # Scans first: a restore holds its lock from before it inserts the scan until after a rollback removes it.
        lock_names = {
            meta["scan_id"]: ARCHIVE_RESTORE_LOCK_TEMPLATE.format(scan_id=meta["scan_id"]) for meta in restored
        }
        held = await lock_repo.held_locks(list(lock_names.values()))
        stale = [meta for meta in restored if lock_names[meta["scan_id"]] not in held]
        if not stale:
            return 0
        stale_scan_ids = [meta["scan_id"] for meta in stale]
        try:
            result = await db.archive_metadata.delete_many({"_id": {"$in": [meta["_id"] for meta in stale]}})
            count: int = result.deleted_count
            if count:
                logger.info(f"Reaped {count} stale archive_metadata entries for restored scans {stale_scan_ids}")
            return count
        except Exception as e:
            logger.warning(f"Failed to delete stale metadata for scans {stale_scan_ids}: {e}")
            return 0

    restored_scans = db.scans.find({**RESTORED_SCAN_MATCH, "restore_in_progress": {"$ne": True}}, {"restored_at": 1})
    return sum([await _reap_batch(batch) async for batch in abatched(restored_scans, batch_size)])


async def _reap_orphan_page(db: Any, page: list[dict[str, Any]], bundle_key: re.Pattern[str], cutoff: datetime) -> int:
    scan_id_by_key = {
        obj["Key"]: match["scan_id"]
        for obj in page
        if (match := bundle_key.fullmatch(obj.get("Key") or "")) and obj.get("LastModified", cutoff) <= cutoff
    }
    if not scan_id_by_key:
        return 0
    known = {
        meta.get("s3_key")
        async for meta in db.archive_metadata.find(
            {"scan_id": {"$in": sorted(set(scan_id_by_key.values()))}}, {"s3_key": 1}
        )
    }
    deleted = 0
    for key in sorted(scan_id_by_key.keys() - known):
        try:
            await delete_object(key)
            deleted += 1
            archive_orphan_objects_reaped_total.inc()
            archive_housekeeping_scans_processed_total.labels(status="orphan_reaped").inc()
            logger.info("Reaped orphan S3 object: %s", key)
        except Exception as e:
            logger.warning("Failed to delete orphan %s: %s", key, e)
    return deleted


async def reap_orphan_s3_objects(db: Any) -> int:
    if not is_archive_enabled():
        return 0

    prefix = archive_key_prefix()
    bundle_key = re.compile(re.escape(prefix) + ARCHIVE_KEY_PATTERN)
    cutoff = datetime.now(timezone.utc) - timedelta(hours=ORPHAN_MIN_AGE_HOURS)
    deleted = 0
    try:
        async for page in list_objects(prefix):
            deleted += await _reap_orphan_page(db, page, bundle_key, cutoff)
    except Exception as e:
        logger.warning("Orphan reaper stopped: %s", e)
    return deleted
