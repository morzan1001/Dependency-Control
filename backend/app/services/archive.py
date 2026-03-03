"""
Archive Service

Handles archiving scan data to S3-compatible storage and restoring it.
Each scan is archived as a single compressed JSON bundle (.json.gz).
"""

import gzip
import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from bson import ObjectId
from motor.motor_asyncio import AsyncIOMotorDatabase, AsyncIOMotorGridFSBucket

from app.core.config import settings
from app.core.constants import ARCHIVE_BUNDLE_VERSION, ARCHIVE_PATH_TEMPLATE
from app.core.s3 import delete_object, download_bytes, is_archive_enabled, upload_bytes
from app.models.archive import ArchiveMetadata
from app.repositories.archive_metadata import ArchiveMetadataRepository

logger = logging.getLogger(__name__)


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
                _serialize_doc(item) if isinstance(item, dict)
                else str(item) if isinstance(item, ObjectId)
                else item.isoformat() if isinstance(item, datetime)
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
            content = await grid_out.read()
            sboms.append({
                "gridfs_id": gid,
                "filename": grid_out.filename,
                "data": json.loads(content),
            })
        except Exception as e:
            logger.warning(f"Failed to load GridFS file {gid}: {e}")

    return sboms


async def archive_scan(
    db: AsyncIOMotorDatabase,  # type: ignore[type-arg]
    scan_id: str,
) -> Optional[ArchiveMetadata]:
    """
    Archive a single scan and all its related data to S3.

    Bundle contents:
    - scan document
    - findings
    - finding_records
    - dependencies
    - analysis_results
    - callgraphs
    - GridFS SBOMs (embedded as JSON)

    Returns ArchiveMetadata on success, None on failure.
    """
    if not is_archive_enabled():
        logger.warning("Archive requested but S3 is not configured.")
        return None

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
        return None

    project_id = scan_doc["project_id"]

    # 2. Collect all related data
    findings = await db.findings.find({"scan_id": scan_id}).to_list(None)
    finding_records = await db.finding_records.find({"scan_id": scan_id}).to_list(None)
    dependencies = await db.dependencies.find({"scan_id": scan_id}).to_list(None)
    analysis_results = await db.analysis_results.find({"scan_id": scan_id}).to_list(None)
    callgraphs = await db.callgraphs.find({"scan_id": scan_id}).to_list(None)

    # 3. Load GridFS SBOMs
    gridfs_ids = _extract_gridfs_ids_from_refs(scan_doc.get("sbom_refs", []))
    gridfs_sboms = await _load_gridfs_sboms(db, gridfs_ids)

    # 4. Build the archive bundle
    bundle = {
        "version": ARCHIVE_BUNDLE_VERSION,
        "archived_at": datetime.now(timezone.utc).isoformat(),
        "scan_id": scan_id,
        "project_id": project_id,
        "scan": _serialize_doc(scan_doc),
        "findings": [_serialize_doc(d) for d in findings],
        "finding_records": [_serialize_doc(d) for d in finding_records],
        "dependencies": [_serialize_doc(d) for d in dependencies],
        "analysis_results": [_serialize_doc(d) for d in analysis_results],
        "callgraphs": [_serialize_doc(d) for d in callgraphs],
        "gridfs_sboms": gridfs_sboms,
    }

    # 5. Serialize to JSON and compress with gzip
    json_bytes = json.dumps(bundle, default=str).encode("utf-8")
    compressed = gzip.compress(json_bytes, compresslevel=6)

    # 6. Upload to S3
    s3_key = ARCHIVE_PATH_TEMPLATE.format(project_id=project_id, scan_id=scan_id)

    try:
        await upload_bytes(s3_key, compressed)
    except Exception as e:
        logger.error(f"Failed to upload archive for scan {scan_id}: {e}")
        return None

    # 7. Create archive metadata record
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
        original_size_bytes=len(json_bytes),
        compressed_size_bytes=len(compressed),
    )

    await repo.create(metadata)

    logger.info(
        f"Archived scan {scan_id} to s3://{settings.S3_BUCKET_NAME}/{s3_key} "
        f"({len(compressed)} bytes compressed)"
    )

    return metadata


async def restore_scan(
    db: AsyncIOMotorDatabase,  # type: ignore[type-arg]
    scan_id: str,
) -> Optional[Dict[str, Any]]:
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

    repo = ArchiveMetadataRepository(db)
    metadata = await repo.find_by_scan_id(scan_id)

    if not metadata:
        logger.error(f"No archive metadata found for scan {scan_id}")
        return None

    # 1. Download from S3
    try:
        compressed = await download_bytes(metadata.s3_key)
    except Exception as e:
        logger.error(f"Failed to download archive for scan {scan_id}: {e}")
        return None

    # 2. Decompress and parse
    json_bytes = gzip.decompress(compressed)
    bundle = json.loads(json_bytes)

    collections_restored: List[str] = []

    # 3. Restore scan document
    scan_doc = bundle.get("scan")
    if scan_doc:
        existing = await db.scans.find_one({"_id": scan_doc["_id"]})
        if existing:
            logger.warning(f"Scan {scan_id} already exists in MongoDB. Skipping restore.")
            return None

        await db.scans.insert_one(scan_doc)
        collections_restored.append("scans")

    # 4. Restore findings
    if bundle.get("findings"):
        await db.findings.insert_many(bundle["findings"], ordered=False)
        collections_restored.append("findings")

    # 5. Restore finding_records
    if bundle.get("finding_records"):
        await db.finding_records.insert_many(bundle["finding_records"], ordered=False)
        collections_restored.append("finding_records")

    # 6. Restore dependencies
    if bundle.get("dependencies"):
        await db.dependencies.insert_many(bundle["dependencies"], ordered=False)
        collections_restored.append("dependencies")

    # 7. Restore analysis_results
    if bundle.get("analysis_results"):
        await db.analysis_results.insert_many(bundle["analysis_results"], ordered=False)
        collections_restored.append("analysis_results")

    # 8. Restore callgraphs
    if bundle.get("callgraphs"):
        await db.callgraphs.insert_many(bundle["callgraphs"], ordered=False)
        collections_restored.append("callgraphs")

    # 9. Re-upload GridFS SBOMs with original IDs
    if bundle.get("gridfs_sboms"):
        fs = AsyncIOMotorGridFSBucket(db)
        for sbom_entry in bundle["gridfs_sboms"]:
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

    # 10. Clean up: delete archive from S3 and metadata from MongoDB
    try:
        await delete_object(metadata.s3_key)
    except Exception as e:
        logger.warning(f"Failed to delete S3 archive after restore: {e}")

    await repo.delete_by_scan_id(scan_id)

    logger.info(
        f"Restored scan {scan_id} from archive. Collections: {collections_restored}"
    )

    return {
        "scan_id": scan_id,
        "project_id": metadata.project_id,
        "collections_restored": collections_restored,
    }
