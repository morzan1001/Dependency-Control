"""Periodic retention sweep deleting compliance reports whose expires_at is in the past."""

import logging
from datetime import datetime, timezone

from bson import ObjectId
from gridfs.errors import NoFile
from motor.motor_asyncio import AsyncIOMotorDatabase, AsyncIOMotorGridFSBucket

from app.repositories.compliance_report import ComplianceReportRepository

logger = logging.getLogger(__name__)


async def delete_report_artifact(db: AsyncIOMotorDatabase, gridfs_id: str | None) -> None:
    """Delete a report's GridFS artifact; one already gone counts as deleted."""
    if not gridfs_id:
        return
    try:
        await AsyncIOMotorGridFSBucket(db).delete(ObjectId(gridfs_id))
    except NoFile:
        pass
    except Exception:
        logger.warning("Failed to delete compliance report artifact %s", gridfs_id, exc_info=True)


async def sweep_expired_compliance_reports(db: AsyncIOMotorDatabase) -> int:
    """Delete expired compliance reports, removing each GridFS artifact before its metadata to avoid orphaned blobs. Returns the count deleted."""
    now = datetime.now(timezone.utc)
    col = db[ComplianceReportRepository.collection_name]
    async for doc in col.find({"expires_at": {"$lt": now}}, {"artifact_gridfs_id": 1}):
        await delete_report_artifact(db, doc.get("artifact_gridfs_id"))
    result = await col.delete_many({"expires_at": {"$lt": now}})
    if result.deleted_count:
        logger.info("Compliance retention sweep deleted %d expired reports", result.deleted_count)
    return result.deleted_count
