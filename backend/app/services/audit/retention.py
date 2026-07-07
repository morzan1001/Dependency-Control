"""Periodic retention cleanup for policy audit entries."""

import logging
from datetime import datetime, timedelta, timezone

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.core.config import settings
from app.repositories.policy_audit_entry import PolicyAuditRepository

logger = logging.getLogger(__name__)

# Crypto and license entries share one collection (discriminated by policy_type);
# prune every discriminator or non-default types accumulate forever.
_POLICY_TYPES = ("crypto", "license")


async def prune_old_audit_entries(db: AsyncIOMotorDatabase) -> int:
    """Prune entries older than the configured retention; returns total deleted (0 if disabled)."""
    days = settings.POLICY_AUDIT_RETENTION_DAYS
    if days <= 0:
        return 0

    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    repo = PolicyAuditRepository(db)

    total = 0
    for policy_type in _POLICY_TYPES:
        total += await repo.delete_older_than(
            policy_scope="system",
            project_id=None,
            cutoff=cutoff,
            policy_type=policy_type,
        )
    distinct = await db[PolicyAuditRepository.collection_name].distinct(
        "project_id",
        {"policy_scope": "project"},
    )
    for pid in distinct:
        if pid is None:
            continue
        for policy_type in _POLICY_TYPES:
            total += await repo.delete_older_than(
                policy_scope="project",
                project_id=pid,
                cutoff=cutoff,
                policy_type=policy_type,
            )
    logger.info("Policy audit retention pruned %d entries (days=%d)", total, days)
    return total
