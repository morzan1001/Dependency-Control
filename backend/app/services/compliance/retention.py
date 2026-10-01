"""Periodic retention sweep deleting compliance reports whose expires_at is in the past."""

import logging
from datetime import datetime, timezone

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.repositories.compliance_report import ComplianceReportRepository

logger = logging.getLogger(__name__)


async def sweep_expired_compliance_reports(db: AsyncIOMotorDatabase) -> int:
    """Delete expired compliance reports and return the count; the orphan reaper frees their artifacts."""
    col = db[ComplianceReportRepository.collection_name]
    result = await col.delete_many({"expires_at": {"$lt": datetime.now(timezone.utc)}})
    if result.deleted_count:
        logger.info("Compliance retention sweep deleted %d expired reports", result.deleted_count)
    return result.deleted_count
