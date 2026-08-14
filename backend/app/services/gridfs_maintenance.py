"""GridFS reference bookkeeping: delete unreferenced SBOM files, reap aged orphans."""

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from bson import ObjectId
from motor.motor_asyncio import AsyncIOMotorGridFSBucket

from app.core.constants import ARCHIVE_ORPHAN_MIN_AGE_HOURS

logger = logging.getLogger(__name__)


def extract_gridfs_ids_from_refs(sbom_refs: list[Any]) -> list[str]:
    """Extract GridFS IDs from a list of SBOM references."""
    ids: list[str] = []
    for ref in sbom_refs:
        if isinstance(ref, dict) and ref.get("type") == "gridfs_reference":
            gid = ref.get("gridfs_id")
            if gid:
                ids.append(gid)
    return ids


async def _surviving_gridfs_references(db: Any, gridfs_ids: list[str], excluded_scan_ids: list[str]) -> set[str]:
    """Return the subset of ``gridfs_ids`` that is still referenced by at
    least one scan outside ``excluded_scan_ids``.
    """
    if not gridfs_ids:
        return set()
    surviving: set[str] = set()
    cursor = db.scans.find(
        {
            "_id": {"$nin": excluded_scan_ids},
            "sbom_refs.gridfs_id": {"$in": gridfs_ids},
        },
        {"sbom_refs": 1},
    )
    async for doc in cursor:
        for gid in extract_gridfs_ids_from_refs(doc.get("sbom_refs", [])):
            if gid in gridfs_ids:
                surviving.add(gid)
    return surviving


async def cleanup_gridfs_files(db: Any, gridfs_ids: list[str], deleted_scan_ids: list[str] | None = None) -> None:
    """Delete GridFS files that no surviving scan still references.

    Rescans copy ``sbom_refs`` (and the ``gridfs_id``) from their source scan, so
    multiple scans can share one GridFS file; deleting it while another scan still
    references it would orphan that reference. ``deleted_scan_ids`` (the scans being
    purged) is excluded from the surviving-reference check.
    """
    if not gridfs_ids:
        return

    surviving = await _surviving_gridfs_references(db, gridfs_ids, deleted_scan_ids or [])

    fs = AsyncIOMotorGridFSBucket(db)
    for gid in gridfs_ids:
        if gid in surviving:
            continue
        try:
            await fs.delete(ObjectId(gid))
        except Exception as e:
            logger.debug(f"GridFS file {gid} already deleted or delete failed: {e}")


async def _referenced_gridfs_ids(db: Any) -> set[str]:
    referenced: set[str] = set()
    cursor = db.scans.find({"sbom_refs": {"$exists": True, "$ne": []}}, {"sbom_refs": 1})
    async for doc in cursor:
        for ref in doc.get("sbom_refs", []):
            if not isinstance(ref, dict):
                continue
            # Collect every id-bearing key so an odd-shaped ref can never cause a deletion.
            for key in ("gridfs_id", "file_id"):
                gid = ref.get(key)
                if gid:
                    referenced.add(str(gid))
    # Compliance report artifacts share the default fs bucket and live for their retention window.
    cursor = db.compliance_reports.find({"artifact_gridfs_id": {"$ne": None}}, {"artifact_gridfs_id": 1})
    async for doc in cursor:
        gid = doc.get("artifact_gridfs_id")
        if gid:
            referenced.add(str(gid))
    return referenced


async def reap_orphan_gridfs_files(db: Any) -> int:
    """Delete GridFS files no scan references, once older than the orphan safety window."""
    referenced = await _referenced_gridfs_ids(db)
    cutoff = datetime.now(timezone.utc) - timedelta(hours=ARCHIVE_ORPHAN_MIN_AGE_HOURS)

    fs = AsyncIOMotorGridFSBucket(db)
    deleted = 0
    async for file_doc in db["fs.files"].find({"uploadDate": {"$lt": cutoff}}, {"_id": 1}):
        file_id = file_doc["_id"]
        if str(file_id) in referenced:
            continue
        try:
            await fs.delete(file_id)
            deleted += 1
        except Exception as e:
            logger.warning(f"Failed to delete orphan GridFS file {file_id}: {e}")
    if deleted:
        logger.info(f"GridFS orphan reaper: deleted {deleted} unreferenced file(s)")
    return deleted
