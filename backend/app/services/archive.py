"""Archive scans as streaming NDJSON bundles to S3 with gzip and optional chunked AES-GCM, lock-guarded per scan_id."""

import asyncio
import contextlib
import json
import logging
import time
import zlib
from collections.abc import AsyncIterator, Awaitable, Callable
from datetime import datetime, timezone
from functools import partial
from typing import Any

from bson import Binary, ObjectId, json_util
from cryptography.exceptions import InvalidTag
from gridfs.errors import FileExists, NoFile
from motor.motor_asyncio import AsyncIOMotorDatabase, AsyncIOMotorGridFSBucket, AsyncIOMotorGridIn
from pymongo.errors import DuplicateKeyError, PyMongoError

from app.core.config import settings
from app.core.constants import (
    ARCHIVE_GRIDFS_CHUNK_FRAME,
    ARCHIVE_GRIDFS_FRAME,
    ARCHIVE_PATH_TEMPLATE,
    ARCHIVE_RESTORE_LOCK_TEMPLATE,
    ENCRYPTION_MAGIC,
    RESTORE_INSERT_BATCH_SIZE,
    RETENTION_PROTECTED_FLAG_VALUES,
    SCAN_ACTIVE_STATUSES,
    SCAN_SCOPED_COLLECTIONS,
)
from app.core.encryption import EncryptionStreamWriter, decrypt_stream, is_encryption_enabled
from app.core.log_utils import sanitize_for_log
from app.core.metrics import (
    ArchiveFailureReason,
    archive_bundle_compressed_bytes,
    archive_failures_total,
    archive_operation_duration_seconds,
    archive_operations_total,
)
from app.core.s3 import (
    delete_object,
    download_stream,
    is_archive_enabled,
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
from app.schemas.archive import ArchiveRestoreResponse
from app.schemas.trufflehog import TruffleHogFinding
from app.services.archive_bundle import (
    BundleFrames,
    BundleStats,
    json_line,
    read_bundle_frames,
    rewrite_bundle_frames,
)
from app.services.gridfs_maintenance import (
    GRIDFS_RESTORE_LOCK_TEMPLATE,
    extract_gridfs_ids_from_refs,
    iter_gridfs_chunks,
)
from app.services.releases import release_protected_scan_ids
from app.services.update_frequency_rollup import record_scan_update_delta

logger = logging.getLogger(__name__)

_ARCHIVE_LOCK_TTL_SECONDS = 600
_GRIDFS_RESTORE_LOCK_POLL_SECONDS = 1
# zlib releases the GIL, so a chunk this large (a whole SBOM line) compresses in a thread instead of stalling the loop.
_COMPRESS_IN_THREAD_MIN_BYTES = 1 << 20

# Collections a bundle may restore into. Marker names are attacker-influenceable (footer
# is a plain sha256, not an HMAC), so any name outside this set must abort the restore.
_RESTORABLE_COLLECTIONS = frozenset({*SCAN_SCOPED_COLLECTIONS, ARCHIVE_GRIDFS_FRAME, ARCHIVE_GRIDFS_CHUNK_FRAME})


class _ArchiveSourceReadError(Exception):
    """A source document could not be read intact; raised to abort the S3 upload so
    housekeeping (which only deletes successfully-archived scans) can't lose data."""


def _hash_plaintext_secrets(collection: str, doc: dict[str, Any]) -> None:
    """Legacy rows and bundles can hold TruffleHog's plaintext Raw; only its digest prefix may leave them."""
    if collection != "analysis_results" or doc.get("analyzer_name") != "trufflehog":
        return
    findings = (doc.get("result") or {}).get("findings")
    if findings:
        doc["result"]["findings"] = [TruffleHogFinding.model_validate(f).model_dump() for f in findings]


async def _hash_plaintext_secrets_in(
    collection: str, docs: AsyncIterator[dict[str, Any]]
) -> AsyncIterator[dict[str, Any]]:
    async for doc in docs:
        _hash_plaintext_secrets(collection, doc)
        yield doc


async def _stream_collection(collection: Any, scan_id: str) -> AsyncIterator[dict[str, Any]]:
    """Yield documents from a collection where scan_id matches."""
    cursor = collection.find({"scan_id": scan_id})
    if hasattr(cursor, "batch_size"):
        cursor = cursor.batch_size(500)
    async for doc in cursor:
        yield doc


async def _stream_gridfs_chunks(db: Any, scan_doc: dict[str, Any]) -> AsyncIterator[dict[str, Any]]:
    """Yield every GridFS file of the scan as ordered chunk frames, each file opening with n=0 even when empty."""
    scan_id = scan_doc["_id"]
    file_ids = dict.fromkeys(
        [
            *extract_gridfs_ids_from_refs(scan_doc.get("sbom_refs", [])),
            *await db.analysis_results.distinct("result_gridfs_id", {"scan_id": scan_id}),
            *await db.callgraphs.distinct("graph_gridfs_id", {"scan_id": scan_id}),
        ]
    )
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
        except Exception as e:
            # Re-raise rather than skip: a dropped file would archive as success while
            # missing data, then housekeeping would delete the source and lose it forever.
            logger.error(
                "Failed to load GridFS file; aborting archive to avoid data loss",
                extra={"gridfs_id": sanitize_for_log(gid), "error": sanitize_for_log(e)},
            )
            raise _ArchiveSourceReadError(str(e)) from e


async def _gzip_compress_stream(source: AsyncIterator[bytes]) -> AsyncIterator[bytes]:
    """Stream-compress with gzip (wbits=31)."""
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
        if not chunk:
            continue
        out = decompressor.decompress(chunk)
        if out:
            yield out
    tail = decompressor.flush()
    if tail:
        yield tail


async def _encrypt_stream(source: AsyncIterator[bytes]) -> AsyncIterator[bytes]:
    """Wrap a byte stream in chunked AES-GCM via a producer task + bounded queue."""
    queue: asyncio.Queue[bytes | None] = asyncio.Queue(maxsize=4)

    async def sink(chunk: bytes) -> None:
        await queue.put(chunk)

    async def producer() -> None:
        writer = EncryptionStreamWriter(sink)
        try:
            await writer.start()
            async for chunk in source:
                await writer.write(chunk)
            await writer.aclose()
        finally:
            await queue.put(None)

    task = asyncio.create_task(producer())
    try:
        while True:
            item = await queue.get()
            if item is None:
                break
            yield item
        await task
    except BaseException:
        task.cancel()
        raise


def _build_archive_payload(
    db: Any,
    scan_doc: dict[str, Any],
    scan_id: str,
    stats: BundleStats,
    bytes_counter: dict[str, int],
) -> tuple[AsyncIterator[bytes], str]:
    """Build the upload payload iterator and its content-type string."""

    async def count_through(it: AsyncIterator[bytes]) -> AsyncIterator[bytes]:
        async for c in it:
            bytes_counter["total"] += len(c)
            yield c

    frames = BundleFrames.write(
        scan_doc=scan_doc,
        collections={
            **{
                name: _hash_plaintext_secrets_in(name, _stream_collection(getattr(db, name), scan_id))
                for name in SCAN_SCOPED_COLLECTIONS
            },
            ARCHIVE_GRIDFS_CHUNK_FRAME: _stream_gridfs_chunks(db, scan_doc),
        },
        stats=stats,
    )
    gzipped = _gzip_compress_stream(frames)
    if is_encryption_enabled():
        return count_through(_encrypt_stream(gzipped)), "application/octet-stream"
    return count_through(gzipped), "application/gzip"


def _count_failure(operation: str, reason: str) -> None:
    archive_failures_total.labels(operation=operation, reason=reason).inc()
    archive_operations_total.labels(operation=operation, status="failure").inc()


async def _drop_upload(s3_key: str, reason: str) -> None:
    """Delete an upload whose metadata this archive must not write, and count the failed archive."""
    try:
        await delete_object(s3_key)
    except Exception:
        logger.exception("Cleanup delete failed for orphan S3 upload")
    _count_failure("archive", reason)


async def _save_archive_metadata(
    repo: ArchiveMetadataRepository,
    scan_doc: dict[str, Any],
    scan_id: str,
    s3_key: str,
    total: int,
    stats: BundleStats,
    archived_at: datetime,
) -> ArchiveMetadata | None:
    """Persist ArchiveMetadata; on unique-key collision delete the S3 orphan and return None."""
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
        scan_completed_at=scan_doc.get("completed_at"),
        scan_status=scan_doc.get("status"),
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
            "Lost archive race, cleaning up our S3 orphan",
            extra={"scan_id": sanitize_for_log(scan_id), "error": sanitize_for_log(e)},
        )
        await _drop_upload(s3_key, ArchiveFailureReason.ALREADY_EXISTS)
        return None
    except Exception as e:
        # The insert may still have landed, so the upload stays; the orphan reaper takes it if nothing points at it.
        logger.warning(
            "Metadata create failed",
            extra={"scan_id": sanitize_for_log(scan_id), "error": sanitize_for_log(e)},
        )
        _count_failure("archive", ArchiveFailureReason.UNKNOWN)
        return None


async def _load_scan_for_archive(
    db: Any,
    repo: ArchiveMetadataRepository,
    scan_id: str,
) -> tuple[ArchiveMetadata | None, dict[str, Any] | None]:
    """Look up the scan for archival, returning (existing_metadata, scan_doc).

    Exactly one is non-None on the happy path; both None means there is nothing to archive (metrics recorded).
    """
    existing = await repo.find_by_scan_id(scan_id)
    scan_doc = await db.scans.find_one({"_id": scan_id})
    if not scan_doc:
        if existing:
            logger.info(
                "Scan already archived, returning existing metadata",
                extra={"scan_id": sanitize_for_log(scan_id)},
            )
            return existing, None
        logger.error(
            "Scan not found for archiving",
            extra={"scan_id": sanitize_for_log(scan_id)},
        )
        _count_failure("archive", ArchiveFailureReason.NOT_FOUND)
        return None, None
    if scan_doc.get("pinned") in RETENTION_PROTECTED_FLAG_VALUES or scan_doc.get("status") in SCAN_ACTIVE_STATUSES:
        logger.info(
            "Scan pinned or under analysis, not archiving it",
            extra={"scan_id": sanitize_for_log(scan_id)},
        )
        _count_failure("archive", ArchiveFailureReason.PROTECTED)
        return None, None
    if existing is None:
        return None, scan_doc
    # A restore since the archive leaves metadata the stale-metadata reaper may delete at any moment.
    if all(scan_doc[field] <= existing.archived_at for field in ("updated_at", "restored_at") if scan_doc.get(field)):
        return existing, None
    # Its bundle lacks what ingest wrote since, and a recreated scan lacks what only the bundle holds.
    logger.warning(
        "Scan written to or restored since it was archived, keeping both",
        extra={"scan_id": sanitize_for_log(scan_id)},
    )
    _count_failure("archive", ArchiveFailureReason.WRITTEN_SINCE_ARCHIVE)
    return None, None


async def _upload_archive_bundle(
    db: Any,
    scan_doc: dict[str, Any],
    scan_id: str,
    s3_key: str,
) -> tuple[int, BundleStats] | None:
    """Build and upload the archive bundle; returns (total_bytes, stats) or None on failure (metrics recorded)."""
    stats = BundleStats()
    bytes_counter: dict[str, int] = {"total": 0}
    payload, content_type = _build_archive_payload(db, scan_doc, scan_id, stats, bytes_counter)
    try:
        total = await upload_stream(s3_key, payload, content_type=content_type)
    except _ArchiveSourceReadError as e:
        logger.error(
            "Aborting archive: source data could not be read intact",
            extra={"scan_id": sanitize_for_log(scan_id), "error": sanitize_for_log(e)},
        )
        _count_failure("archive", ArchiveFailureReason.INTEGRITY)
        return None
    except Exception as e:
        logger.exception(
            "Failed to upload archive",
            extra={"scan_id": sanitize_for_log(scan_id), "error": sanitize_for_log(e)},
        )
        _count_failure("archive", ArchiveFailureReason.S3_ERROR)
        return None
    archive_bundle_compressed_bytes.observe(total)
    return total, stats


async def archive_scan(
    db: AsyncIOMotorDatabase,  # type: ignore[type-arg]
    scan_id: str,
) -> ArchiveMetadata | None:
    """Archive one scan and its related data to S3 under a distributed lock on archive:{scan_id}.

    Returns ArchiveMetadata on success; None on lock-held, not-found, protected, or upload failure.
    """
    if not is_archive_enabled():
        logger.warning("Archive requested but S3 is not configured.")
        return None

    repo = ArchiveMetadataRepository(db)
    lock_repo = DistributedLocksRepository(db)
    lock_name = f"archive:{scan_id}"
    holder = new_lock_holder()

    if not await lock_repo.acquire_lock(lock_name, holder, ttl_seconds=_ARCHIVE_LOCK_TTL_SECONDS):
        logger.info(
            "Archive of scan skipped, lock held by another worker",
            extra={"scan_id": sanitize_for_log(scan_id)},
        )
        _count_failure("archive", ArchiveFailureReason.LOCK_HELD)
        return None

    try:
        # Taken before the scan is read, so any ingest the bundle may have missed is dated after it.
        archived_at = datetime.now(timezone.utc)
        existing, scan_doc = await _load_scan_for_archive(db, repo, scan_id)
        if existing is not None:
            return existing
        if scan_doc is None:
            return None

        # Archival removes the scan document, which would orphan release resolution.
        if await release_protected_scan_ids(db, [scan_id]):
            logger.info(
                "Archive of release scan refused",
                extra={"scan_id": sanitize_for_log(scan_id)},
            )
            _count_failure("archive", ArchiveFailureReason.RELEASE_PROTECTED)
            return None

        project_id = scan_doc["project_id"]
        archived_at_unix = int(archived_at.timestamp())
        s3_key = ARCHIVE_PATH_TEMPLATE.format(project_id=project_id, scan_id=scan_id, archived_at_unix=archived_at_unix)

        renew_lock = partial(lock_repo.renew_lock, lock_name, holder, _ARCHIVE_LOCK_TTL_SECONDS)
        start_time = time.monotonic()
        try:
            upload = _upload_archive_bundle(db, scan_doc, scan_id, s3_key)
            upload_result = await run_holding_lock(renew_lock, _ARCHIVE_LOCK_TTL_SECONDS, upload)
            # A pod that took the lock over archives on its own, possibly while this archive's delete runs.
            if upload_result is not None and not await renew_lock():
                raise LockLost
        except LockLost:
            logger.error(
                "Archive lost its lock to another worker, dropping its upload",
                extra={"scan_id": sanitize_for_log(scan_id)},
            )
            await _drop_upload(s3_key, ArchiveFailureReason.LOCK_HELD)
            return None
        except PyMongoError:
            logger.exception(
                "Archive could not confirm its lock, dropping its upload", extra={"scan_id": sanitize_for_log(scan_id)}
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
            "archive.success",
            extra={
                "scan_id": scan_id,
                "project_id": project_id,
                "s3_key": s3_key,
                "compressed_bytes": total,
                "findings": stats.findings,
                "dependencies": stats.dependencies,
            },
        )
        return metadata
    finally:
        await lock_repo.release_lock(lock_name, holder)


async def _open_bundle_stream(metadata: ArchiveMetadata) -> AsyncIterator[bytes]:
    """Yield a decompressed (and, if encrypted, decrypted) byte stream for the bundle.

    Encryption is detected by sniffing the ENCRYPTION_MAGIC prefix, not the live
    ``is_encryption_enabled()`` flag, since each bundle was written under whatever config
    existed at archive time and there is no per-bundle marker.
    """
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
    doc = json_util.loads(line)
    _hash_plaintext_secrets(collection, doc)
    return json_line(doc)


def stream_bundle_for_download(metadata: ArchiveMetadata) -> AsyncIterator[bytes]:
    """Stream the bundle as unencrypted gzip NDJSON, TruffleHog plaintext hashed and the footer digest recomputed."""
    return _gzip_compress_stream(rewrite_bundle_frames(_open_bundle_stream(metadata), _hash_plaintext_secrets_in_line))


# ---------------------------------------------------------------------------
# restore_scan helpers
# ---------------------------------------------------------------------------


def _parse_error_reason(exc: ValueError) -> str:
    """Map a bundle ValueError to the appropriate ArchiveFailureReason string."""
    return ArchiveFailureReason.VERSION_MISMATCH if "version" in str(exc).lower() else ArchiveFailureReason.INTEGRITY


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


async def _handle_header_event(
    db: Any,
    data: dict[str, Any],
    collections_restored: list[str],
) -> None:
    """Insert the scan doc from a header event, marked as a restore still in progress.

    Version validation lives in ``read_bundle_frames``, which raises before yielding a
    header with a mismatched version, so no version check is needed here.
    """
    scan_data = data["scan"]
    scan_data["pinned"] = True
    # restored_at is the reaper's evidence of a finished restore; a re-archived scan's bundle carries its old one.
    scan_data.pop("restored_at", None)
    scan_data["restore_in_progress"] = True
    await db.scans.insert_one(scan_data)
    collections_restored.append("scans")


async def _handle_doc_event(
    db: Any,
    event: dict[str, Any],
    batch_by_collection: dict[str, list[dict[str, Any]]],
    collections_restored: list[str],
) -> None:
    coll = event["collection"]
    doc = event["data"]
    _hash_plaintext_secrets(coll, doc)
    batch_by_collection.setdefault(coll, []).append(doc)
    if len(batch_by_collection[coll]) >= RESTORE_INSERT_BATCH_SIZE:
        await _flush_batches(db, batch_by_collection, collections_restored)


class _GridFSRestore:
    """Writes chunk frames file by file, each under a lock shared by every restore of that file id."""

    def __init__(self, db: Any) -> None:
        self._db = db
        self._locks = DistributedLocksRepository(db)
        self._holder = new_lock_holder()
        self._lock_name: str | None = None
        self._grid_in: AsyncIOMotorGridIn | None = None
        self._renew_at = 0.0

    async def write(self, frame: dict[str, Any]) -> None:
        """n=0 closes the previous file and opens this one unless it is already stored."""
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
    """The chunk frame for a gridfs_sboms entry, which carries a whole SBOM as parsed JSON."""
    return {
        "_id": ObjectId(entry["gridfs_id"]),
        "filename": entry["filename"],
        "n": 0,
        "data": json.dumps(entry["data"]).encode(),
    }


async def _replay_bundle(
    db: Any,
    scan_id: str,
    decompressed: AsyncIterator[bytes],
) -> tuple[str | None, list[str]]:
    """Read bundle frames, insert scan + batched collections and GridFS files.

    Returns (failure_reason_or_None, collections_restored).
    """
    collections_restored: list[str] = []
    batch_by_collection: dict[str, list[dict[str, Any]]] = {}
    gridfs = _GridFSRestore(db)

    try:
        async for event in read_bundle_frames(decompressed):
            etype = event["type"]
            if etype == "header":
                await _handle_header_event(db, event["data"], collections_restored)
            elif etype == "doc":
                coll = event["collection"]
                if coll not in _RESTORABLE_COLLECTIONS:
                    # Marker names come from unauthenticated bundle content (footer is a plain sha256,
                    # not an HMAC); refuse unknown names so a crafted marker can't write into arbitrary collections.
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
                    await _handle_doc_event(db, event, batch_by_collection, collections_restored)
            elif etype == "footer":
                await gridfs.close()
                await _flush_batches(db, batch_by_collection, collections_restored)
                break
    except ValueError as e:
        logger.exception(
            "Restore parse error",
            extra={"scan_id": sanitize_for_log(scan_id), "error": sanitize_for_log(e)},
        )
        return _parse_error_reason(e), collections_restored
    except PyMongoError as e:
        logger.exception(
            "Restore MongoDB error",
            extra={"scan_id": sanitize_for_log(scan_id), "error": sanitize_for_log(e)},
        )
        return ArchiveFailureReason.UNKNOWN, collections_restored
    except InvalidTag as e:
        logger.exception(
            "Restore decryption error",
            extra={"scan_id": sanitize_for_log(scan_id), "error": sanitize_for_log(e)},
        )
        return ArchiveFailureReason.ENCRYPTION, collections_restored
    except Exception as e:
        logger.exception(
            "Restore stream error",
            extra={"scan_id": sanitize_for_log(scan_id), "error": sanitize_for_log(e)},
        )
        return ArchiveFailureReason.S3_ERROR, collections_restored
    finally:
        with contextlib.suppress(PyMongoError):
            await gridfs.abort()

    return None, collections_restored


async def _rollback_partial_restore(db: Any, scan_id: str) -> None:
    """Best-effort cleanup of the MongoDB state a failed or abandoned restore left behind.

    The scan doc goes last, so a failed cleanup leaves it marked restore_in_progress for the next restore to retry.
    """
    try:
        for coll in SCAN_SCOPED_COLLECTIONS:
            await getattr(db, coll).delete_many({"scan_id": scan_id})
        await db.scans.delete_one({"_id": scan_id})
    except Exception as e:
        logger.warning(
            "Partial-restore rollback failed",
            extra={"scan_id": sanitize_for_log(scan_id), "error": sanitize_for_log(e)},
        )


async def _load_restore_metadata(
    db: Any,
    repo: ArchiveMetadataRepository,
    scan_id: str,
) -> ArchiveMetadata | None:
    """Return restore metadata once an unfinished restore's leftovers are rolled back.

    Returns None (metrics recorded) if the metadata is missing or the scan exists without restore_in_progress.
    """
    metadata = await repo.find_by_scan_id(scan_id)
    if not metadata:
        logger.error(
            "No archive metadata for scan",
            extra={"scan_id": sanitize_for_log(scan_id)},
        )
        _count_failure("restore", ArchiveFailureReason.NOT_FOUND)
        return None

    existing = await db.scans.find_one({"_id": scan_id}, {"restore_in_progress": 1})
    if existing and existing.get("restore_in_progress"):
        # A running restore keeps renewing its lock, so while we hold it nobody still writes this leftover.
        logger.warning(
            "Rolling back an unfinished restore before restoring again",
            extra={"scan_id": sanitize_for_log(scan_id)},
        )
        await _rollback_partial_restore(db, scan_id)
    elif existing:
        logger.warning(
            "Scan already exists in MongoDB, aborting restore",
            extra={"scan_id": sanitize_for_log(scan_id)},
        )
        _count_failure("restore", ArchiveFailureReason.ALREADY_EXISTS)
        return None

    return metadata


async def _finalize_restore_cleanup(
    repo: ArchiveMetadataRepository,
    metadata: ArchiveMetadata,
    scan_id: str,
) -> None:
    """Delete the metadata record, then the S3 object, after a successful restore.

    A failed deletion is logged, not rolled back. The object goes only after its metadata, so no metadata
    is ever left pointing at a deleted bundle; the stale-metadata and orphan reapers sweep what remains.
    """
    try:
        await repo.delete_by_scan_id(scan_id)
    except Exception as e:
        logger.warning(
            "Metadata delete failed after restore; the stale-metadata reaper will retry",
            extra={"scan_id": sanitize_for_log(scan_id), "error": sanitize_for_log(e)},
        )
        return
    try:
        await delete_object(metadata.s3_key, bucket=metadata.s3_bucket)
    except Exception as e:
        logger.warning(
            "S3 delete failed after restore; orphan reaper will retry",
            extra={
                "scan_id": sanitize_for_log(scan_id),
                "s3_key": sanitize_for_log(metadata.s3_key),
                "error": sanitize_for_log(e),
            },
        )


async def _mark_restore_complete(
    db: Any,
    scan_id: str,
    renew_lock: Callable[[], Awaitable[bool]],
) -> str | None:
    """Stamp the scan restored if this restore still owns it; otherwise return the failure reason."""
    # The heartbeat checks the lock only every TTL/3, so a takeover in between must still be caught before finalize.
    if not await renew_lock():
        logger.error(
            "Restore lost its lock to another restore, leaving the scan to it",
            extra={"scan_id": sanitize_for_log(scan_id)},
        )
        return ArchiveFailureReason.LOCK_HELD
    completed = await db.scans.update_one(
        {"_id": scan_id, "restore_in_progress": True},
        {"$set": {"restored_at": datetime.now(timezone.utc)}, "$unset": {"restore_in_progress": ""}},
    )
    if completed.matched_count == 0:
        logger.error(
            "Restored scan disappeared before the restore completed",
            extra={"scan_id": sanitize_for_log(scan_id)},
        )
        await _rollback_partial_restore(db, scan_id)
        return ArchiveFailureReason.UNKNOWN
    return None


async def _abandon_restore(
    db: Any,
    scan_id: str,
    renew_lock: Callable[[], Awaitable[bool]],
    reason: str,
) -> str:
    """Roll back a failed restore's writes while it still owns the scan's restore lock; return the failure reason."""
    try:
        still_held = await renew_lock()
    except PyMongoError as e:
        # The leftover keeps its restore_in_progress flag, so the next restore rolls it back.
        logger.warning(
            "Restore could not confirm it still holds its lock, leaving the rollback to the next restore",
            extra={"scan_id": sanitize_for_log(scan_id), "error": sanitize_for_log(e)},
        )
    else:
        if still_held:
            await _rollback_partial_restore(db, scan_id)
        else:
            logger.error(
                "Restore lost its lock to another restore, leaving the scan to it",
                extra={"scan_id": sanitize_for_log(scan_id)},
            )
            reason = ArchiveFailureReason.LOCK_HELD
    return reason


async def _run_restore_pipeline(
    db: Any,
    repo: ArchiveMetadataRepository,
    metadata: ArchiveMetadata,
    scan_id: str,
    renew_lock: Callable[[], Awaitable[bool]],
) -> ArchiveRestoreResponse | None:
    """Drive the replay+GridFS+cleanup pipeline after preconditions are met."""
    start_time = time.monotonic()
    decompressed = _open_bundle_stream(metadata)
    failure_reason, collections_restored = await _replay_bundle(db, scan_id, decompressed)
    if failure_reason is None:
        failure_reason = await _mark_restore_complete(db, scan_id, renew_lock)
    elif "scans" in collections_restored:
        # Before its header insert the restore wrote nothing, and a scan already there belongs to an ingest.
        failure_reason = await _abandon_restore(db, scan_id, renew_lock, failure_reason)
    if failure_reason is not None:
        _count_failure("restore", failure_reason)
        return None

    # The restored scan re-enters its branch timeline, so the rollup also re-points the successor.
    await record_scan_update_delta(db, scan_id)

    await _finalize_restore_cleanup(repo, metadata, scan_id)

    duration = time.monotonic() - start_time
    archive_operations_total.labels(operation="restore", status="success").inc()
    archive_operation_duration_seconds.labels(operation="restore").observe(duration)
    logger.info(
        "archive.restore.success",
        extra={
            "scan_id": scan_id,
            "project_id": metadata.project_id,
            "collections_restored": collections_restored,
        },
    )
    return ArchiveRestoreResponse(
        scan_id=scan_id,
        project_id=metadata.project_id,
        collections_restored=collections_restored,
    )


async def restore_scan(
    db: AsyncIOMotorDatabase,  # type: ignore[type-arg]
    scan_id: str,
) -> ArchiveRestoreResponse | None:
    """Restore an archived scan back to MongoDB under a distributed lock on restore:{scan_id}.

    An unfinished restore's leftovers (restore_in_progress) are rolled back and replayed; any other
    existing scan aborts the restore.
    """
    if not is_archive_enabled():
        return None

    repo = ArchiveMetadataRepository(db)
    lock_repo = DistributedLocksRepository(db)
    lock_name = ARCHIVE_RESTORE_LOCK_TEMPLATE.format(scan_id=scan_id)
    holder = new_lock_holder()
    renew_lock = partial(lock_repo.renew_lock, lock_name, holder, _ARCHIVE_LOCK_TTL_SECONDS)

    if not await lock_repo.acquire_lock(lock_name, holder, ttl_seconds=_ARCHIVE_LOCK_TTL_SECONDS):
        logger.info(
            "Restore of scan blocked, lock held",
            extra={"scan_id": sanitize_for_log(scan_id)},
        )
        _count_failure("restore", ArchiveFailureReason.LOCK_HELD)
        return None

    try:
        metadata = await _load_restore_metadata(db, repo, scan_id)
        if metadata is None:
            return None
        pipeline = _run_restore_pipeline(db, repo, metadata, scan_id, renew_lock)
        return await run_holding_lock(renew_lock, _ARCHIVE_LOCK_TTL_SECONDS, pipeline)
    except LockLost:
        logger.error(
            "Restore lost its lock to another restore, aborting",
            extra={"scan_id": sanitize_for_log(scan_id)},
        )
        _count_failure("restore", ArchiveFailureReason.LOCK_HELD)
        return None
    finally:
        await lock_repo.release_lock(lock_name, holder)
