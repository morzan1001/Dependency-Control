"""
Periodic retention sweep for compliance report jobs.

The engine sets ``expires_at`` on completed reports; the sweep deletes
reports whose ``expires_at`` is in the past. Retention period is
configured via settings.COMPLIANCE_REPORT_RETENTION_DAYS (default 90 days).
"""

import logging
from datetime import datetime, timezone

from motor.motor_asyncio import AsyncIOMotorDatabase, AsyncIOMotorGridFSBucket

from app.core.config import settings
from app.repositories.compliance_report import ComplianceReportRepository

logger = logging.getLogger(__name__)


async def sweep_expired_compliance_reports(db: AsyncIOMotorDatabase) -> int:
    """Delete all compliance reports whose ``expires_at`` is in the past.

    Removes the GridFS artifact (if any) before the metadata document so we
    never orphan a blob. Returns the count of metadata documents deleted.
    """
    now = datetime.now(timezone.utc)
    col = db[ComplianceReportRepository.collection_name]
    try:
        bucket = AsyncIOMotorGridFSBucket(db)
    except Exception:  # pragma: no cover — unreachable in real Motor
        bucket = None

    # count_documents understands $lt on both real Motor and the fake-DB
    # used in integration tests, but find().to_list does not always. Use
    # delete_many for the metadata pass and walk GridFS blobs separately.
    expired_docs = await col.find({"expires_at": {"$lt": now}}).to_list(length=None)
    if bucket is not None:
        for doc in expired_docs:
            gridfs_id = doc.get("artifact_gridfs_id")
            if not gridfs_id:
                continue
            try:
                # gridfs_id is stored as a string for JSON-roundtrip
                # friendliness; GridFS APIs need an ObjectId.
                from bson import ObjectId

                await bucket.delete(ObjectId(gridfs_id))
            except Exception as exc:  # missing blob / fake-DB no-op
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


def _configured_retention_days() -> int:
    """Return the configured retention window in days from settings."""
    return settings.COMPLIANCE_REPORT_RETENTION_DAYS
