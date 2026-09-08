"""The stuck-scan recovery window: a scan inside it belongs to the worker still running it.

Recovery resets `processing` back to `pending` and requeues it, so a scan wrongly judged stuck
loses the analysis in flight and is run a second time.
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock

import pytest

from app.core.config import settings
from app.core.constants import HOUSEKEEPING_MAX_SCAN_RETRIES
from app.core.housekeeping import recover_stuck_scans
from tests.mocks.fake_mongo import FakeDatabase

_TIMEOUT = timedelta(seconds=settings.HOUSEKEEPING_STUCK_SCAN_TIMEOUT_SECONDS)
_WELL_INSIDE_TIMEOUT = _TIMEOUT / 2
_WELL_PAST_TIMEOUT = _TIMEOUT * 2


async def _run_recovery(monkeypatch, scan: dict):
    db = FakeDatabase()
    await db.scans.insert_one(scan)
    monkeypatch.setattr("app.core.housekeeping.get_database", AsyncMock(return_value=db))
    worker_manager = AsyncMock()
    await recover_stuck_scans(worker_manager)
    return await db.scans.find_one({"_id": scan["_id"]}), worker_manager


def _processing_scan(started_ago: timedelta, **overrides) -> dict:
    scan = {
        "_id": "scan-1",
        "status": "processing",
        "analysis_started_at": datetime.now(timezone.utc) - started_ago,
    }
    scan.update(overrides)
    return scan


@pytest.mark.asyncio
async def test_a_scan_inside_the_timeout_is_left_alone(monkeypatch):
    scan, worker_manager = await _run_recovery(monkeypatch, _processing_scan(_WELL_INSIDE_TIMEOUT))

    assert scan["status"] == "processing"
    assert scan.get("retry_count") is None
    worker_manager.add_job.assert_not_awaited()


@pytest.mark.asyncio
async def test_a_scan_past_the_timeout_is_reset_and_requeued(monkeypatch):
    scan, worker_manager = await _run_recovery(monkeypatch, _processing_scan(_WELL_PAST_TIMEOUT))

    assert scan["status"] == "pending"
    assert scan["retry_count"] == 1
    worker_manager.add_job.assert_awaited_once_with("scan-1")


@pytest.mark.asyncio
async def test_a_scan_out_of_retries_fails_instead_of_requeueing(monkeypatch):
    scan, worker_manager = await _run_recovery(
        monkeypatch,
        _processing_scan(_WELL_PAST_TIMEOUT, retry_count=HOUSEKEEPING_MAX_SCAN_RETRIES),
    )

    assert scan["status"] == "failed"
    worker_manager.add_job.assert_not_awaited()
