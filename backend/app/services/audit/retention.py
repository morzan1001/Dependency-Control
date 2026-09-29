"""Periodic retention cleanup for policy audit entries."""

import logging
from datetime import datetime, timedelta, timezone

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.core.config import settings
from app.repositories.policy_audit_entry import PolicyAuditRepository

logger = logging.getLogger(__name__)


async def prune_old_audit_entries(db: AsyncIOMotorDatabase) -> int:
    """Prune entries older than the configured retention; returns total deleted (0 if disabled)."""
    days = settings.POLICY_AUDIT_RETENTION_DAYS
    if days <= 0:
        return 0

    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    total = await PolicyAuditRepository(db).delete_all_older_than(cutoff)
    logger.info("Policy audit retention pruned %d entries (days=%d)", total, days)
    return total
