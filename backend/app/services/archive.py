"""Archive scans as streaming NDJSON bundles to S3 with gzip and optional chunked AES-GCM, lock-guarded per scan_id."""

import asyncio
import json
import logging
import os
import time
import zlib
from datetime import datetime, timezone
from typing import Any, AsyncIterator, Dict, List, Optional, Tuple

from bson import ObjectId
from cryptography.exceptions import InvalidTag
from motor.motor_asyncio import AsyncIOMotorDatabase, AsyncIOMotorGridFSBucket
from pymongo.errors import DuplicateKeyError, PyMongoError

from app.core.config import settings
from app.core.constants import (
    ARCHIVE_PATH_TEMPLATE,
    ENCRYPTION_MAGIC,
    RESTORE_INSERT_BATCH_SIZE,
)
from app.core.encryption import EncryptionStreamWriter, decrypt_stream, is_encryption_enabled
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
from app.repositories.distributed_locks import DistributedLocksRepository
from app.schemas.archive import ArchiveRestoreResponse
from app.services.archive_bundle import BundleFrames, BundleStats, read_bundle_frames

logger = logging.getLogger(__name__)

_ARCHIVE_LOCK_TTL_SECONDS = 600

# Collections a bundle may restore into. Marker names are attacker-influenceable (footer
# is a plain sha256, not an HMAC), so any name outside this set must abort the restore.
_RESTORABLE_COLLECTIONS = frozenset(
    {
        "findings",
        "finding_records",
        "dependencies",
        "analysis_results",
        "callgraphs",
        "crypto_assets",
        "gridfs_sboms",
    }
)


class _ArchiveSourceReadError(Exception):
    """A source document could not be read intact; raised to abort the S3 upload so
    housekeeping (which only deletes successfully-archived scans) can't lose data."""


def _sanitize_for_log(value: Any, max_len: int = 200) -> str:
    """Strip CR/LF and bound length so a hostile value can't forge log lines or balloon volume."""
    s = str(value)
    s = s.replace("\r", " ").replace("\n", " ").replace("\t", " ")
    if len(s) > max_len:
        s = s[:max_len] + "...<truncated>"
    return s


def _holder_id(prefix: str) -> str:
    return f"{prefix}-{os.getenv('HOSTNAME', 'unknown')}"


def _extract_gridfs_ids_from_refs(sbom_refs: List[Any]) -> List[str]:
    """Extract GridFS IDs from a list of SBOM references."""
    ids: List[str] = []
    for ref in sbom_refs:
        if isinstance(ref, dict) and ref.get("type") == "gridfs_reference":
            gid = ref.get("gridfs_id")
            if gid:
                ids.append(str(gid))
    return ids


async def _stream_collection(collection: Any, scan_id: str) -> AsyncIterator[Dict[str, Any]]:
    """Yield documents from a collection where scan_id matches."""
    cursor = collection.find({"scan_id": scan_id})
    if hasattr(cursor, "batch_size"):
        cursor = cursor.batch_size(500)
    async for doc in cursor:
        yield doc


async def _stream_gridfs_sboms(db: Any, scan_doc: Dict[str, Any]) -> AsyncIterator[Dict[str, Any]]:
    """Yield one frame per GridFS SBOM (gridfs_id, filename, data)."""
    gridfs_ids = _extract_gridfs_ids_from_refs(scan_doc.get("sbom_refs", []))
    if not gridfs_ids:
        return
    fs = AsyncIOMotorGridFSBucket(db)
    for gid in gridfs_ids:
        try:
            grid_out = await fs.open_download_stream(ObjectId(gid))
            content: bytes = await grid_out.read()
            yield {
                "gridfs_id": str(gid),
                "filename": grid_out.filename,
                "data": json.loads(content),
            }
        except Exception as e:
            # Re-raise rather than skip: a dropped SBOM would archive as success while
            # missing data, then housekeeping would delete the source and lose it forever.
            logger.error(
                "Failed to load GridFS file; aborting archive to avoid data loss",
                extra={"gridfs_id": _sanitize_for_log(gid), "error": _sanitize_for_log(e)},
            )
            raise _ArchiveSourceReadError(str(e)) from e


async def _gzip_compress_stream(source: AsyncIterator[bytes]) -> AsyncIterator[bytes]:
    """Stream-compress with gzip (wbits=31)."""
    compressor = zlib.compressobj(level=6, wbits=31)
    async for chunk in source:
        if not chunk:
            continue
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
    queue: asyncio.Queue[Optional[bytes]] = asyncio.Queue(maxsize=4)

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
    scan_doc: Dict[str, Any],
    scan_id: str,
    stats: BundleStats,
    bytes_counter: Dict[str, int],
) -> Tuple[AsyncIterator[bytes], str]:
    """Build the upload payload iterator and its content-type string."""

    async def count_through(it: AsyncIterator[bytes]) -> AsyncIterator[bytes]:
        async for c in it:
            bytes_counter["total"] += len(c)
            yield c

    frames = BundleFrames.write(
        scan_doc=scan_doc,
        collections={
            "findings": _stream_collection(db.findings, scan_id),
            "finding_records": _stream_collection(db.finding_records, scan_id),
            "dependencies": _stream_collection(db.dependencies, scan_id),
            "analysis_results": _stream_collection(db.analysis_results, scan_id),
            "callgraphs": _stream_collection(db.callgraphs, scan_id),
            "crypto_assets": _stream_collection(db.crypto_assets, scan_id),
            "gridfs_sboms": _stream_gridfs_sboms(db, scan_doc),
        },
        stats=stats,
    )
    gzipped = _gzip_compress_stream(frames)
    if is_encryption_enabled():
        return count_through(_encrypt_stream(gzipped)), "application/octet-stream"
    return count_through(gzipped), "application/gzip"


async def _save_archive_metadata(
    repo: ArchiveMetadataRepository,
    scan_doc: Dict[str, Any],
    scan_id: str,
    s3_key: str,
    total: int,
    stats: BundleStats,
) -> Optional[ArchiveMetadata]:
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
    )
    try:
        await repo.create(metadata)
        return metadata
    except DuplicateKeyError as e:
        # Another worker won the metadata insert; its upload is authoritative, clean up ours.
        logger.info(
            "Lost archive race, cleaning up our S3 orphan",
            extra={"scan_id": _sanitize_for_log(scan_id), "error": _sanitize_for_log(e)},
        )
        try:
            await delete_object(s3_key)
        except Exception:
            logger.exception("Cleanup delete failed for orphan S3 upload")
        archive_failures_total.labels(operation="archive", reason=ArchiveFailureReason.ALREADY_EXISTS).inc()
        archive_operations_total.labels(operation="archive", status="failure").inc()
        return None
    except Exception as e:
        logger.warning(
            "Metadata create failed, cleaning up S3 object",
            extra={"scan_id": _sanitize_for_log(scan_id), "error": _sanitize_for_log(e)},
        )
        try:
            await delete_object(s3_key)
        except Exception:
            logger.exception("Cleanup delete failed for orphan S3 upload")
        archive_failures_total.labels(operation="archive", reason=ArchiveFailureReason.UNKNOWN).inc()
        archive_operations_total.labels(operation="archive", status="failure").inc()
        return None


async def _load_scan_for_archive(
    db: Any,
    repo: ArchiveMetadataRepository,
    scan_id: str,
) -> Tuple[Optional[ArchiveMetadata], Optional[Dict[str, Any]]]:
    """Look up the scan for archival, returning (existing_metadata, scan_doc).

    Exactly one is non-None on the happy path; both None means not-found (metrics recorded).
    """
    existing = await repo.find_by_scan_id(scan_id)
    if existing:
        logger.info(
            "Scan already archived, returning existing metadata",
            extra={"scan_id": _sanitize_for_log(scan_id)},
        )
        return existing, None

    scan_doc = await db.scans.find_one({"_id": scan_id})
    if not scan_doc:
        logger.error(
            "Scan not found for archiving",
            extra={"scan_id": _sanitize_for_log(scan_id)},
        )
        archive_failures_total.labels(operation="archive", reason=ArchiveFailureReason.NOT_FOUND).inc()
        archive_operations_total.labels(operation="archive", status="failure").inc()
        return None, None

    return None, scan_doc


async def _upload_archive_bundle(
    db: Any,
    scan_doc: Dict[str, Any],
    scan_id: str,
    s3_key: str,
) -> Optional[Tuple[int, BundleStats]]:
    """Build and upload the archive bundle; returns (total_bytes, stats) or None on failure (metrics recorded)."""
    stats = BundleStats()
    bytes_counter: Dict[str, int] = {"total": 0}
    payload, content_type = _build_archive_payload(db, scan_doc, scan_id, stats, bytes_counter)
    try:
        total = await upload_stream(s3_key, payload, content_type=content_type)
    except _ArchiveSourceReadError as e:
        logger.error(
            "Aborting archive: source data could not be read intact",
            extra={"scan_id": _sanitize_for_log(scan_id), "error": _sanitize_for_log(e)},
        )
        archive_failures_total.labels(operation="archive", reason=ArchiveFailureReason.INTEGRITY).inc()
        archive_operations_total.labels(operation="archive", status="failure").inc()
        return None
    except Exception as e:
        logger.exception(
            "Failed to upload archive",
            extra={"scan_id": _sanitize_for_log(scan_id), "error": _sanitize_for_log(e)},
        )
        archive_failures_total.labels(operation="archive", reason=ArchiveFailureReason.S3_ERROR).inc()
        archive_operations_total.labels(operation="archive", status="failure").inc()
        return None
    archive_bundle_compressed_bytes.observe(total)
    return total, stats


async def archive_scan(
    db: AsyncIOMotorDatabase,  # type: ignore[type-arg]
    scan_id: str,
) -> Optional[ArchiveMetadata]:
    """Archive one scan and its related data to S3 under a distributed lock on archive:{scan_id}.

    Returns ArchiveMetadata on success; None on lock-held, not-found, or upload failure.
    """
    if not is_archive_enabled():
        logger.warning("Archive requested but S3 is not configured.")
        return None

    repo = ArchiveMetadataRepository(db)
    lock_repo = DistributedLocksRepository(db)
    lock_name = f"archive:{scan_id}"
    holder = _holder_id("archive")

    if not await lock_repo.acquire_lock(lock_name, holder, ttl_seconds=_ARCHIVE_LOCK_TTL_SECONDS):
        logger.info(
            "Archive of scan skipped, lock held by another worker",
            extra={"scan_id": _sanitize_for_log(scan_id)},
        )
        archive_failures_total.labels(operation="archive", reason=ArchiveFailureReason.LOCK_HELD).inc()
        archive_operations_total.labels(operation="archive", status="failure").inc()
        return None

    try:
        existing, scan_doc = await _load_scan_for_archive(db, repo, scan_id)
        if existing is not None:
            return existing
        if scan_doc is None:
            return None

        project_id = scan_doc["project_id"]
        archived_at_unix = int(datetime.now(timezone.utc).timestamp())
        s3_key = ARCHIVE_PATH_TEMPLATE.format(project_id=project_id, scan_id=scan_id, archived_at_unix=archived_at_unix)

        start_time = time.monotonic()
        upload_result = await _upload_archive_bundle(db, scan_doc, scan_id, s3_key)
        if upload_result is None:
            return None
        total, stats = upload_result

        metadata = await _save_archive_metadata(repo, scan_doc, scan_id, s3_key, total, stats)
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


# ---------------------------------------------------------------------------
# restore_scan helpers
# ---------------------------------------------------------------------------


async def _open_restore_stream(metadata: ArchiveMetadata) -> AsyncIterator[bytes]:
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


def _parse_error_reason(exc: ValueError) -> str:
    """Map a bundle ValueError to the appropriate ArchiveFailureReason string."""
    return ArchiveFailureReason.VERSION_MISMATCH if "version" in str(exc).lower() else ArchiveFailureReason.INTEGRITY


async def _flush_batch(
    db: Any,
    coll_name: str,
    batch_by_collection: Dict[str, List[Dict[str, Any]]],
    collections_restored: List[str],
) -> None:
    docs = batch_by_collection.pop(coll_name, None)
    if not docs:
        return
    await getattr(db, coll_name).insert_many(docs, ordered=False)
    if coll_name not in collections_restored:
        collections_restored.append(coll_name)


async def _handle_header_event(
    db: Any,
    data: Dict[str, Any],
    collections_restored: List[str],
) -> None:
    """Insert the scan doc from a header event.

    Version validation lives in ``read_bundle_frames``, which raises before yielding a
    header with a mismatched version, so no version check is needed here.
    """
    scan_data = data.get("scan")
    if scan_data:
        scan_data["pinned"] = True
        await db.scans.insert_one(scan_data)
        collections_restored.append("scans")


async def _handle_doc_event(
    db: Any,
    event: Dict[str, Any],
    batch_by_collection: Dict[str, List[Dict[str, Any]]],
    gridfs_entries: List[Dict[str, Any]],
    collections_restored: List[str],
) -> None:
    coll = event["collection"]
    if coll not in _RESTORABLE_COLLECTIONS:
        # Marker names come from unauthenticated bundle content (footer is a plain sha256,
        # not an HMAC); refuse unknown names so a crafted marker can't write into arbitrary collections.
        raise ValueError(f"Unexpected collection in bundle: {_sanitize_for_log(coll)}")
    if coll == "gridfs_sboms":
        gridfs_entries.append(event["data"])
        return
    batch_by_collection.setdefault(coll, []).append(event["data"])
    if len(batch_by_collection[coll]) >= RESTORE_INSERT_BATCH_SIZE:
        await _flush_batch(db, coll, batch_by_collection, collections_restored)


async def _replay_bundle(
    db: Any,
    scan_id: str,
    decompressed: AsyncIterator[bytes],
) -> Tuple[Optional[str], List[str], List[Dict[str, Any]]]:
    """Read bundle frames, insert scan + batched collections, collect GridFS entries.

    Returns (failure_reason_or_None, collections_restored, gridfs_entries).
    """
    collections_restored: List[str] = []
    batch_by_collection: Dict[str, List[Dict[str, Any]]] = {}
    gridfs_entries: List[Dict[str, Any]] = []

    try:
        async for event in read_bundle_frames(decompressed):
            etype = event["type"]
            if etype == "header":
                await _handle_header_event(db, event["data"], collections_restored)
            elif etype == "doc":
                await _handle_doc_event(db, event, batch_by_collection, gridfs_entries, collections_restored)
            elif etype == "footer":
                for coll in tuple(batch_by_collection):
                    await _flush_batch(db, coll, batch_by_collection, collections_restored)
                break
    except ValueError as e:
        logger.exception(
            "Restore parse error",
            extra={"scan_id": _sanitize_for_log(scan_id), "error": _sanitize_for_log(e)},
        )
        return _parse_error_reason(e), collections_restored, gridfs_entries
    except PyMongoError as e:
        logger.exception(
            "Restore MongoDB error",
            extra={"scan_id": _sanitize_for_log(scan_id), "error": _sanitize_for_log(e)},
        )
        return ArchiveFailureReason.UNKNOWN, collections_restored, gridfs_entries
    except InvalidTag as e:
        logger.exception(
            "Restore decryption error",
            extra={"scan_id": _sanitize_for_log(scan_id), "error": _sanitize_for_log(e)},
        )
        return ArchiveFailureReason.ENCRYPTION, collections_restored, gridfs_entries
    except Exception as e:
        logger.exception(
            "Restore stream error",
            extra={"scan_id": _sanitize_for_log(scan_id), "error": _sanitize_for_log(e)},
        )
        return ArchiveFailureReason.S3_ERROR, collections_restored, gridfs_entries

    return None, collections_restored, gridfs_entries


async def _restore_gridfs(
    db: Any,
    scan_id: str,
    gridfs_entries: List[Dict[str, Any]],
) -> bool:
    """Re-upload GridFS SBOMs from bundle entries. Returns True on full success."""
    fs = AsyncIOMotorGridFSBucket(db)
    failures: List[str] = []
    for entry in gridfs_entries:
        try:
            grid_id = ObjectId(entry["gridfs_id"])
            # Delete first for retry-safety: upload_from_stream_with_id rejects duplicates
            # a prior failed restore may have left behind.
            try:
                await fs.delete(grid_id)
            except Exception:
                pass
            await fs.upload_from_stream_with_id(
                grid_id,
                entry.get("filename", "restored.json"),
                json.dumps(entry["data"]).encode("utf-8"),
            )
        except Exception as e:
            logger.exception(
                "GridFS restore failed",
                extra={
                    "gridfs_id": _sanitize_for_log(entry.get("gridfs_id")),
                    "error": _sanitize_for_log(e),
                },
            )
            failures.append(entry.get("gridfs_id", "?"))
    if failures:
        logger.error(
            "Restore incomplete, GridFS files failed",
            extra={"scan_id": _sanitize_for_log(scan_id), "failed_count": len(failures)},
        )
        return False
    return True


async def _rollback_partial_restore(db: Any, scan_id: str) -> None:
    """Best-effort cleanup of partial MongoDB state after a restore failure.

    _replay_bundle inserts the scan doc before collections, so a mid-stream failure can
    leave partial state that makes a retry hit the ALREADY_EXISTS guard and never recover.
    """
    try:
        await db.scans.delete_one({"_id": scan_id})
        for coll in (
            "findings",
            "finding_records",
            "dependencies",
            "analysis_results",
            "callgraphs",
            "crypto_assets",
        ):
            await getattr(db, coll).delete_many({"scan_id": scan_id})
    except Exception as e:
        logger.warning(
            "Partial-restore rollback failed",
            extra={"scan_id": _sanitize_for_log(scan_id), "error": _sanitize_for_log(e)},
        )


async def _load_restore_metadata(
    db: Any,
    repo: ArchiveMetadataRepository,
    scan_id: str,
) -> Optional[ArchiveMetadata]:
    """Return restore metadata, or None (metrics recorded) if it's missing or the scan already exists."""
    metadata = await repo.find_by_scan_id(scan_id)
    if not metadata:
        logger.error(
            "No archive metadata for scan",
            extra={"scan_id": _sanitize_for_log(scan_id)},
        )
        archive_failures_total.labels(operation="restore", reason=ArchiveFailureReason.NOT_FOUND).inc()
        archive_operations_total.labels(operation="restore", status="failure").inc()
        return None

    existing = await db.scans.find_one({"_id": scan_id})
    if existing:
        logger.warning(
            "Scan already exists in MongoDB, aborting restore",
            extra={"scan_id": _sanitize_for_log(scan_id)},
        )
        archive_failures_total.labels(operation="restore", reason=ArchiveFailureReason.ALREADY_EXISTS).inc()
        archive_operations_total.labels(operation="restore", status="failure").inc()
        return None

    return metadata


async def _finalize_restore_cleanup(
    repo: ArchiveMetadataRepository,
    metadata: ArchiveMetadata,
    scan_id: str,
) -> None:
    """Delete the S3 object and metadata record after a successful restore.

    Either deletion failing is logged but does not roll back — the orphan reaper sweeps
    remnants. The metadata MUST be removed: the scan is back in MongoDB, so stale metadata
    would block future re-archival via archive_scan's existing-metadata short-circuit.
    """
    try:
        await delete_object(metadata.s3_key, bucket=metadata.s3_bucket)
    except Exception as e:
        logger.warning(
            "S3 delete failed after restore; orphan reaper will retry",
            extra={
                "scan_id": _sanitize_for_log(scan_id),
                "s3_key": _sanitize_for_log(metadata.s3_key),
                "error": _sanitize_for_log(e),
            },
        )
    try:
        await repo.delete_by_scan_id(scan_id)
    except Exception as e:
        logger.warning(
            "Metadata delete failed after restore; orphan reaper will retry",
            extra={"scan_id": _sanitize_for_log(scan_id), "error": _sanitize_for_log(e)},
        )


async def _run_restore_pipeline(
    db: Any,
    repo: ArchiveMetadataRepository,
    metadata: ArchiveMetadata,
    scan_id: str,
) -> Optional[ArchiveRestoreResponse]:
    """Drive the replay+GridFS+cleanup pipeline after preconditions are met."""
    start_time = time.monotonic()
    decompressed = _open_restore_stream(metadata)
    failure_reason, collections_restored, gridfs_entries = await _replay_bundle(db, scan_id, decompressed)

    if failure_reason is not None:
        await _rollback_partial_restore(db, scan_id)
        archive_failures_total.labels(operation="restore", reason=failure_reason).inc()
        archive_operations_total.labels(operation="restore", status="failure").inc()
        return None

    if gridfs_entries and not await _restore_gridfs(db, scan_id, gridfs_entries):
        await _rollback_partial_restore(db, scan_id)
        archive_failures_total.labels(operation="restore", reason=ArchiveFailureReason.INTEGRITY).inc()
        archive_operations_total.labels(operation="restore", status="failure").inc()
        return None
    if gridfs_entries:
        collections_restored.append("gridfs_sboms")

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
) -> Optional[ArchiveRestoreResponse]:
    """Restore an archived scan back to MongoDB under a distributed lock on restore:{scan_id}.

    Aborts if the scan already exists. On success, deletes the S3 archive and metadata;
    either deletion failing is logged but the orphan reaper sweeps remnants.
    """
    if not is_archive_enabled():
        return None

    repo = ArchiveMetadataRepository(db)
    lock_repo = DistributedLocksRepository(db)
    lock_name = f"restore:{scan_id}"
    holder = _holder_id("restore")

    if not await lock_repo.acquire_lock(lock_name, holder, ttl_seconds=_ARCHIVE_LOCK_TTL_SECONDS):
        logger.info(
            "Restore of scan blocked, lock held",
            extra={"scan_id": _sanitize_for_log(scan_id)},
        )
        archive_failures_total.labels(operation="restore", reason=ArchiveFailureReason.LOCK_HELD).inc()
        archive_operations_total.labels(operation="restore", status="failure").inc()
        return None

    try:
        metadata = await _load_restore_metadata(db, repo, scan_id)
        if metadata is None:
            return None
        return await _run_restore_pipeline(db, repo, metadata, scan_id)
    finally:
        await lock_repo.release_lock(lock_name, holder)
