"""Periodic retention sweep for compliance reports: fails the ones a dead pod left unfinished, deletes expired ones."""

import logging
from datetime import datetime, timedelta, timezone

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.core.config import settings
from app.core.constants import COMPLIANCE_REPORT_STUCK_AFTER_HOURS
from app.repositories.compliance_report import ComplianceReportRepository
from app.schemas.compliance import ReportStatus

logger = logging.getLogger(__name__)


async def sweep_expired_compliance_reports(db: AsyncIOMotorDatabase) -> int:
    """Fail reports left unfinished, delete expired ones and return that count; the orphan reaper frees artifacts."""
    col = db[ComplianceReportRepository.collection_name]
    now = datetime.now(timezone.utc)
    stuck = await col.update_many(
        {
            "status": {"$in": [ReportStatus.PENDING.value, ReportStatus.GENERATING.value]},
            "requested_at": {"$lt": now - timedelta(hours=COMPLIANCE_REPORT_STUCK_AFTER_HOURS)},
        },
        {
            "$set": {
                "status": ReportStatus.FAILED.value,
                "error_message": "Generation was interrupted; request the report again.",
                "completed_at": now,
                "expires_at": now + timedelta(days=settings.COMPLIANCE_REPORT_RETENTION_DAYS),
            }
        },
    )
    if stuck.modified_count:
        logger.warning("Compliance retention sweep failed %d interrupted reports", stuck.modified_count)
    result = await col.delete_many({"expires_at": {"$lt": now}})
    if result.deleted_count:
        logger.info("Compliance retention sweep deleted %d expired reports", result.deleted_count)
    return result.deleted_count
