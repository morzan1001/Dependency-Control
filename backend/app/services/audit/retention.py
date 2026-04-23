"""
Periodic retention cleanup for policy audit entries.

If POLICY_AUDIT_RETENTION_DAYS env-var is set, delete system + every
per-project audit entry older than (now - N days). Unset env = forever.
"""

import logging
import os
from datetime import datetime, timedelta, timezone

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.repositories.policy_audit_entry import PolicyAuditRepository

logger = logging.getLogger(__name__)


async def prune_old_audit_entries(db: AsyncIOMotorDatabase) -> int:
    """Prune entries older than POLICY_AUDIT_RETENTION_DAYS.
    Returns the total deleted count across all scopes. 0 if not configured."""
    days_str = os.environ.get("POLICY_AUDIT_RETENTION_DAYS")
    if not days_str:
        return 0
    try:
        days = int(days_str)
    except ValueError:
        logger.warning("Invalid POLICY_AUDIT_RETENTION_DAYS: %r", days_str)
        return 0
    if days <= 0:
        return 0

    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    repo = PolicyAuditRepository(db)

    total = 0
    total += await repo.delete_older_than(
        policy_scope="system",
        project_id=None,
        cutoff=cutoff,
    )
    # Per-project retention: iterate distinct project_ids
    distinct = await db[PolicyAuditRepository.COLLECTION].distinct(
        "project_id",
        {"policy_scope": "project"},
    )
    for pid in distinct:
        if pid is None:
            continue
        total += await repo.delete_older_than(
            policy_scope="project",
            project_id=pid,
            cutoff=cutoff,
        )
    logger.info("Policy audit retention pruned %d entries (days=%d)", total, days)
    return total
