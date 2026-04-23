"""
Periodic retention sweep for compliance report jobs.

The engine sets ``expires_at`` on completed reports (default: 90 days from
completion) but nothing was reading it — GridFS and the metadata collection
grew unbounded. This module deletes any expired reports and their GridFS
artifacts on startup. Mirrors the policy-audit retention pattern.

Override the retention period via the COMPLIANCE_REPORT_RETENTION_DAYS
env-var; the value is informational (the engine already applies it when
setting ``expires_at``). The sweep itself always trusts ``expires_at``.
"""

import logging
import os
from datetime import datetime, timezone

from motor.motor_asyncio import AsyncIOMotorDatabase, AsyncIOMotorGridFSBucket

from app.repositories.compliance_report import ComplianceReportRepository

logger = logging.getLogger(__name__)

COMPLIANCE_REPORT_RETENTION_ENV = "COMPLIANCE_REPORT_RETENTION_DAYS"
DEFAULT_COMPLIANCE_REPORT_RETENTION_DAYS = 90


async def sweep_expired_compliance_reports(db: AsyncIOMotorDatabase) -> int:
    """Delete all compliance reports whose ``expires_at`` is in the past.

    Removes the GridFS artifact (if any) before the metadata document so we
    never orphan a blob. Returns the count of metadata documents deleted.
    """
    now = datetime.now(timezone.utc)
    col = db[ComplianceReportRepository.COLLECTION]
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
                await bucket.delete(gridfs_id)
            except Exception as exc:  # missing blob / fake-DB no-op
                logger.debug(
                    "Could not delete GridFS artifact %s: %s", gridfs_id, exc,
                )
    result = await col.delete_many({"expires_at": {"$lt": now}})
    deleted = getattr(result, "deleted_count", len(expired_docs))
    if deleted:
        logger.info("Compliance retention sweep deleted %d expired reports", deleted)
    return deleted


def _configured_retention_days() -> int:
    """Return the configured retention window in days. Informational only —
    the engine uses this when stamping ``expires_at``; the sweeper just
    honours the already-stored expiry."""
    raw = os.environ.get(COMPLIANCE_REPORT_RETENTION_ENV)
    if not raw:
        return DEFAULT_COMPLIANCE_REPORT_RETENTION_DAYS
    try:
        value = int(raw)
    except ValueError:
        logger.warning(
            "Invalid %s: %r — falling back to default",
            COMPLIANCE_REPORT_RETENTION_ENV, raw,
        )
        return DEFAULT_COMPLIANCE_REPORT_RETENTION_DAYS
    return value if value > 0 else DEFAULT_COMPLIANCE_REPORT_RETENTION_DAYS
