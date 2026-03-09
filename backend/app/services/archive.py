"""
Archive Service

Handles archiving scan data to S3-compatible storage and restoring it.
Each scan is archived as a single compressed JSON bundle (.json.gz).

Memory-efficient: uses streaming writes during archival and batched inserts
during restore to avoid loading entire scan datasets into RAM.
"""

import gzip
import io
import json
import logging
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from bson import ObjectId
from motor.motor_asyncio import AsyncIOMotorDatabase, AsyncIOMotorGridFSBucket
from pydantic import BaseModel

from app.core.config import settings
from app.core.constants import ARCHIVE_BUNDLE_VERSION, ARCHIVE_PATH_TEMPLATE
from app.core.encryption import decrypt, encrypt, is_encryption_enabled
from app.core.s3 import delete_object, download_bytes, is_archive_enabled, upload_bytes
from app.core.metrics import (
    archive_bundle_compressed_bytes,
    archive_operation_duration_seconds,
    archive_operations_total,
)
from app.models.archive import ArchiveMetadata
from app.repositories.archive_metadata import ArchiveMetadataRepository
from app.schemas.archive import ArchiveRestoreResponse

logger = logging.getLogger(__name__)

_STREAMING_BATCH_SIZE = 500
_RESTORE_BATCH_SIZE = 1000


class ArchiveStats(BaseModel):
    """Tracks collection counts during streaming archive creation."""

    findings: int = 0
    finding_records: int = 0
    dependencies: int = 0
    analysis_results: int = 0
    callgraphs: int = 0
    critical_findings: int = 0
    high_findings: int = 0


def _serialize_doc(doc: Dict[str, Any]) -> Dict[str, Any]:
    """
    Convert MongoDB document to JSON-serializable dict.
    Handles ObjectId and datetime conversion recursively.
    """
    result: Dict[str, Any] = {}
    for key, value in doc.items():
        if isinstance(value, ObjectId):
            result[key] = str(value)
        elif isinstance(value, datetime):
            result[key] = value.isoformat()
        elif isinstance(value, dict):
            result[key] = _serialize_doc(value)
        elif isinstance(value, list):
            result[key] = [
                _serialize_doc(item)
                if isinstance(item, dict)
                else str(item)
                if isinstance(item, ObjectId)
                else item.isoformat()
                if isinstance(item, datetime)
                else item
                for item in value
            ]
        else:
            result[key] = value
    return result


def _extract_gridfs_ids_from_refs(sbom_refs: List[Any]) -> List[str]:
    """Extract GridFS IDs from SBOM references."""
    ids: List[str] = []
    for ref in sbom_refs:
        if isinstance(ref, dict) and ref.get("type") == "gridfs_reference":
            gid = ref.get("gridfs_id")
            if gid:
                ids.append(gid)
    return ids


async def _load_gridfs_sboms(
    db: AsyncIOMotorDatabase,  # type: ignore[type-arg]
    gridfs_ids: List[str],
) -> List[Dict[str, Any]]:
    """Load SBOM data from GridFS and return as list of dicts."""
    if not gridfs_ids:
        return []

    fs = AsyncIOMotorGridFSBucket(db)
    sboms: List[Dict[str, Any]] = []

    for gid in gridfs_ids:
        try:
            grid_out = await fs.open_download_stream(ObjectId(gid))
            content: bytes = await grid_out.read()
            sboms.append(
                {
                    "gridfs_id": gid,
                    "filename": grid_out.filename,
                    "data": json.loads(content),
                }
            )
        except Exception as e:
            logger.warning(f"Failed to load GridFS file {gid}: {e}")

    return sboms


async def _stream_collection_to_gzip(
    gz: gzip.GzipFile,
    cursor: Any,
    stats: ArchiveStats,
    field_name: str,
) -> None:
    """Stream a MongoDB cursor as a JSON array into the gzip writer.

    Processes documents in batches to limit peak memory usage.
    Tracks finding severity counts in-place via the shared stats object.
    """
    gz.write(b"[")
    count = 0
    async for doc in cursor.batch_size(_STREAMING_BATCH_SIZE):
        if count > 0:
            gz.write(b",")
        gz.write(json.dumps(_serialize_doc(doc), default=str).encode("utf-8"))
        count += 1
        if field_name == "findings":
            severity = doc.get("severity", "")
            if severity == "CRITICAL":
                stats.critical_findings += 1
            elif severity == "HIGH":
                stats.high_findings += 1
    gz.write(b"]")
    setattr(stats, field_name, count)


async def archive_scan(
    db: AsyncIOMotorDatabase,  # type: ignore[type-arg]
    scan_id: str,
) -> Optional[ArchiveMetadata]:
    """
    Archive a single scan and all its related data to S3.

    Uses streaming gzip compression — only one batch of documents is held in
    memory at a time instead of loading all collections at once.

    Returns ArchiveMetadata on success, None on failure.
    """
    if not is_archive_enabled():
        logger.warning("Archive requested but S3 is not configured.")
        return None

    start_time = time.monotonic()

    # Check if already archived
    repo = ArchiveMetadataRepository(db)
    existing = await repo.find_by_scan_id(scan_id)
    if existing:
        logger.info(f"Scan {scan_id} is already archived. Skipping.")
        return existing

    # 1. Load the scan document
    scan_doc = await db.scans.find_one({"_id": scan_id})
    if not scan_doc:
        logger.error(f"Scan {scan_id} not found for archiving.")
        archive_operations_total.labels(operation="archive", status="failure").inc()
        return None

    project_id = scan_doc["project_id"]
    stats = ArchiveStats()

    # 2. Stream collections into a compressed gzip archive.
    buf = io.BytesIO()
    try:
        gz = gzip.GzipFile(fileobj=buf, mode="wb", compresslevel=6)
        try:
            # Write JSON object start + header fields manually to avoid
            # the fragile "remove trailing }" trick.
            gz.write(b"{")
            gz.write(json.dumps("version").encode("utf-8"))
            gz.write(b":")
            gz.write(json.dumps(ARCHIVE_BUNDLE_VERSION).encode("utf-8"))

            for key in ("archived_at", "scan_id", "project_id", "scan"):
                gz.write(b",")
                gz.write(json.dumps(key).encode("utf-8"))
                gz.write(b":")
                value: Any
                if key == "archived_at":
                    value = datetime.now(timezone.utc).isoformat()
                elif key == "scan_id":
                    value = scan_id
                elif key == "project_id":
                    value = project_id
                else:  # scan
                    value = _serialize_doc(scan_doc)
                gz.write(json.dumps(value, default=str).encode("utf-8"))

            # Stream each collection
            for field_name, collection in [
                ("findings", db.findings),
                ("finding_records", db.finding_records),
                ("dependencies", db.dependencies),
                ("analysis_results", db.analysis_results),
                ("callgraphs", db.callgraphs),
            ]:
                gz.write(b",")
                gz.write(json.dumps(field_name).encode("utf-8"))
                gz.write(b":")
                cursor = collection.find({"scan_id": scan_id})
                await _stream_collection_to_gzip(gz, cursor, stats, field_name)

            # GridFS SBOMs (typically a small number of files)
            gridfs_ids = _extract_gridfs_ids_from_refs(scan_doc.get("sbom_refs", []))
            gridfs_sboms = await _load_gridfs_sboms(db, gridfs_ids)
            gz.write(b',"gridfs_sboms":')
            gz.write(json.dumps(gridfs_sboms, default=str).encode("utf-8"))

            gz.write(b"}")
        finally:
            gz.close()

        compressed = buf.getvalue()
    finally:
        buf.close()

    archive_bundle_compressed_bytes.observe(len(compressed))

    # 3. Encrypt if configured
    upload_data = encrypt(compressed) if is_encryption_enabled() else compressed

    # 4. Upload to S3
    s3_key = ARCHIVE_PATH_TEMPLATE.format(project_id=project_id, scan_id=scan_id)

    try:
        await upload_bytes(s3_key, upload_data)
    except Exception as e:
        logger.error(f"Failed to upload archive for scan {scan_id}: {e}")
        archive_operations_total.labels(operation="archive", status="failure").inc()
        return None

    # 5. Create archive metadata record
    metadata = ArchiveMetadata(
        project_id=project_id,
        scan_id=scan_id,
        s3_key=s3_key,
        s3_bucket=settings.S3_BUCKET_NAME,
        branch=scan_doc.get("branch"),
        commit_hash=scan_doc.get("commit_hash"),
        scan_created_at=scan_doc.get("created_at"),
        scan_completed_at=scan_doc.get("completed_at"),
        scan_status=scan_doc.get("status"),
        original_size_bytes=None,
        compressed_size_bytes=len(compressed),
        findings_count=stats.findings,
        critical_findings_count=stats.critical_findings,
        high_findings_count=stats.high_findings,
        dependencies_count=stats.dependencies,
        sbom_filenames=[s["filename"] for s in gridfs_sboms if s.get("filename")],
    )

    await repo.create(metadata)

    duration = time.monotonic() - start_time
    archive_operations_total.labels(operation="archive", status="success").inc()
    archive_operation_duration_seconds.labels(operation="archive").observe(duration)

    logger.info(
        f"Archived scan {scan_id} to s3://{settings.S3_BUCKET_NAME}/{s3_key} "
        f"({len(compressed)} bytes, {stats.findings} findings, {stats.dependencies} deps)"
    )

    return metadata


async def _restore_collection_batched(
    collection: Any,
    docs: List[Dict[str, Any]],
) -> None:
    """Insert documents in batches to limit memory pressure during restore."""
    for i in range(0, len(docs), _RESTORE_BATCH_SIZE):
        batch = docs[i : i + _RESTORE_BATCH_SIZE]
        await collection.insert_many(batch, ordered=False)


async def restore_scan(
    db: AsyncIOMotorDatabase,  # type: ignore[type-arg]
    scan_id: str,
) -> Optional[ArchiveRestoreResponse]:
    """
    Restore a scan and all related data from S3 archive back to MongoDB.

    Steps:
    1. Find archive metadata
    2. Download and decompress from S3
    3. Insert scan, findings, finding_records, dependencies,
       analysis_results, callgraphs back into MongoDB
    4. Re-upload GridFS SBOMs
    5. Delete archive metadata and S3 object

    Returns dict with restore details on success, None on failure.
    """
    if not is_archive_enabled():
        return None

    start_time = time.monotonic()

    repo = ArchiveMetadataRepository(db)
    metadata = await repo.find_by_scan_id(scan_id)

    if not metadata:
        logger.error(f"No archive metadata found for scan {scan_id}")
        archive_operations_total.labels(operation="restore", status="failure").inc()
        return None

    # 1. Download from S3
    try:
        raw_data = await download_bytes(metadata.s3_key)
    except Exception as e:
        logger.error(f"Failed to download archive for scan {scan_id}: {e}")
        archive_operations_total.labels(operation="restore", status="failure").inc()
        return None

    # 1b. Decrypt if encryption is configured
    compressed = decrypt(raw_data) if is_encryption_enabled() else raw_data

    # 2. Decompress and parse
    json_bytes = gzip.decompress(compressed)
    bundle = json.loads(json_bytes)
    # Free the intermediate bytes immediately
    del json_bytes, compressed, raw_data

    collections_restored: List[str] = []

    # 3. Restore scan document
    scan_doc = bundle.get("scan")
    if scan_doc:
        existing = await db.scans.find_one({"_id": scan_doc["_id"]})
        if existing:
            logger.warning(f"Scan {scan_id} already exists in MongoDB. Skipping restore.")
            archive_operations_total.labels(operation="restore", status="failure").inc()
            return None

        scan_doc["pinned"] = True
        await db.scans.insert_one(scan_doc)
        collections_restored.append("scans")

    # 4-8. Restore collections in batches, freeing each after insert
    for field_name, collection in [
        ("findings", db.findings),
        ("finding_records", db.finding_records),
        ("dependencies", db.dependencies),
        ("analysis_results", db.analysis_results),
        ("callgraphs", db.callgraphs),
    ]:
        docs = bundle.pop(field_name, [])
        if docs:
            await _restore_collection_batched(collection, docs)
            collections_restored.append(field_name)
            del docs

    # 9. Re-upload GridFS SBOMs with original IDs
    gridfs_sboms = bundle.pop("gridfs_sboms", [])
    if gridfs_sboms:
        fs = AsyncIOMotorGridFSBucket(db)
        for sbom_entry in gridfs_sboms:
            try:
                sbom_data = json.dumps(sbom_entry["data"]).encode("utf-8")
                grid_id = ObjectId(sbom_entry["gridfs_id"])
                await fs.upload_from_stream_with_id(
                    grid_id,
                    sbom_entry.get("filename", "restored.json"),
                    sbom_data,
                )
            except Exception as e:
                logger.warning(f"Failed to restore GridFS file: {e}")
        collections_restored.append("gridfs_sboms")

    del bundle

    # 10. Clean up: delete archive from S3 and metadata from MongoDB
    try:
        await delete_object(metadata.s3_key)
    except Exception as e:
        logger.warning(f"Failed to delete S3 archive after restore: {e}")

    await repo.delete_by_scan_id(scan_id)

    duration = time.monotonic() - start_time
    archive_operations_total.labels(operation="restore", status="success").inc()
    archive_operation_duration_seconds.labels(operation="restore").observe(duration)

    logger.info(f"Restored scan {scan_id} from archive. Collections: {collections_restored}")

    return ArchiveRestoreResponse(
        scan_id=scan_id,
        project_id=metadata.project_id,
        collections_restored=collections_restored,
    )
