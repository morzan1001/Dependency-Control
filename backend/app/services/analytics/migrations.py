"""
Idempotent backfill for findings.scan_created_at.

Findings emitted pre-Phase-2 didn't carry scan_created_at. Trend queries
rely on this field so the aggregation can bucket by scan time without a
$lookup on scans.

Run once on startup; short-circuits when no docs lack the field.
"""

import logging

from motor.motor_asyncio import AsyncIOMotorDatabase
from pymongo import UpdateOne

logger = logging.getLogger(__name__)


async def backfill_scan_created_at(
    db: AsyncIOMotorDatabase, batch_size: int = 1000,
) -> int:
    """Backfill `findings.scan_created_at` from the owning scan's `created_at`.

    Returns the number of documents patched. Safe to re-run.
    """
    patched = 0
    cursor = db.findings.find(
        {"scan_created_at": {"$exists": False}},
        {"_id": 1, "scan_id": 1},
        batch_size=batch_size,
    )
    batch: list = []
    scan_cache: dict = {}
    async for doc in cursor:
        scan_id = doc.get("scan_id")
        if not scan_id:
            continue
        if scan_id not in scan_cache:
            scan_doc = await db.scans.find_one({"_id": scan_id}, {"created_at": 1})
            scan_cache[scan_id] = scan_doc.get("created_at") if scan_doc else None
        ts = scan_cache[scan_id]
        if ts is None:
            continue
        batch.append(UpdateOne(
            {"_id": doc["_id"]},
            {"$set": {"scan_created_at": ts}},
        ))
        if len(batch) >= batch_size:
            result = await db.findings.bulk_write(batch, ordered=False)
            patched += result.modified_count
            batch = []

    if batch:
        result = await db.findings.bulk_write(batch, ordered=False)
        patched += result.modified_count

    logger.info("backfill_scan_created_at: patched %d finding docs", patched)
    return patched
