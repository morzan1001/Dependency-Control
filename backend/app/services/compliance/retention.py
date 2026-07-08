"""Periodic retention sweep deleting compliance reports whose expires_at is in the past."""

import logging
from datetime import datetime, timezone

from motor.motor_asyncio import AsyncIOMotorDatabase, AsyncIOMotorGridFSBucket

from app.repositories.compliance_report import ComplianceReportRepository

logger = logging.getLogger(__name__)


async def sweep_expired_compliance_reports(db: AsyncIOMotorDatabase) -> int:
    """Delete expired compliance reports, removing each GridFS artifact before its metadata to avoid orphaned blobs. Returns the count deleted."""
    now = datetime.now(timezone.utc)
    col = db[ComplianceReportRepository.collection_name]
    try:
        bucket = AsyncIOMotorGridFSBucket(db)
    except Exception:  # pragma: no cover
        bucket = None

    expired_docs = await col.find({"expires_at": {"$lt": now}}).to_list(length=None)
    if bucket is not None:
        for doc in expired_docs:
            gridfs_id = doc.get("artifact_gridfs_id")
            if not gridfs_id:
                continue
            try:
                # gridfs_id is stored as a string; GridFS APIs need an ObjectId.
                from bson import ObjectId

                await bucket.delete(ObjectId(gridfs_id))
            except Exception as exc:
                logger.debug(
                    "Could not delete GridFS artifact %s: %s",
                    gridfs_id,
                    exc,
                )
    result = await col.delete_many({"expires_at": {"$lt": now}})
    deleted = getattr(result, "deleted_count", len(expired_docs))
    if deleted:
        logger.info("Compliance retention sweep deleted %d expired reports", deleted)
    return deleted
