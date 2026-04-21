from datetime import datetime, timezone

import pytest

from app.services.analytics.migrations import backfill_scan_created_at


@pytest.mark.asyncio
async def test_migration_backfills_scan_created_at(db):
    scan_date = datetime(2026, 3, 1, tzinfo=timezone.utc)
    await db.scans.insert_one({"_id": "scan1", "created_at": scan_date})
    await db.findings.insert_one({
        "_id": "f1", "scan_id": "scan1",
    })
    await db.findings.insert_one({
        "_id": "f2", "scan_id": "scan1",
        "scan_created_at": scan_date,
    })

    n = await backfill_scan_created_at(db, batch_size=10)
    assert n == 1

    doc = await db.findings.find_one({"_id": "f1"})
    assert doc["scan_created_at"] == scan_date


@pytest.mark.asyncio
async def test_migration_is_idempotent(db):
    scan_date = datetime(2026, 3, 1, tzinfo=timezone.utc)
    await db.scans.insert_one({"_id": "scanX", "created_at": scan_date})
    await db.findings.insert_one({"_id": "fX", "scan_id": "scanX"})

    n1 = await backfill_scan_created_at(db)
    n2 = await backfill_scan_created_at(db)
    assert n1 == 1
    assert n2 == 0
