"""Which pending scans get force-aggregated.

A scan aggregated too early publishes stats over a partial result set; a scan never aggregated
stays pending forever with findings nobody counts.
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock

import pytest

from app.core.constants import HOUSEKEEPING_STALE_SCAN_THRESHOLD_SECONDS
from app.core.housekeeping import trigger_stale_pending_scans
from tests.mocks.fake_mongo import FakeDatabase

_THRESHOLD = timedelta(seconds=HOUSEKEEPING_STALE_SCAN_THRESHOLD_SECONDS)
_WELL_INSIDE = _THRESHOLD / 2
_WELL_PAST = _THRESHOLD * 2
_SCANNER = "trufflehog"


def _pending_scan(scan_id: str, last_result_ago: timedelta | None, **overrides) -> dict:
    scan: dict = {"_id": scan_id, "status": "pending", "received_results": [_SCANNER]}
    if last_result_ago is not None:
        scan["last_result_at"] = datetime.now(timezone.utc) - last_result_ago
    scan.update(overrides)
    return scan


async def _run(monkeypatch, *scans) -> AsyncMock:
    db = FakeDatabase()
    for scan in scans:
        await db.scans.insert_one(scan)
    monkeypatch.setattr("app.core.housekeeping.get_database", AsyncMock(return_value=db))
    worker_manager = AsyncMock()
    await trigger_stale_pending_scans(worker_manager)
    return worker_manager


def _queued(worker_manager: AsyncMock) -> list[str]:
    return [call.args[0] for call in worker_manager.add_job.await_args_list]


@pytest.mark.asyncio
async def test_a_pending_scan_whose_last_result_has_gone_stale_is_aggregated(monkeypatch):
    worker_manager = await _run(monkeypatch, _pending_scan("stale", _WELL_PAST))

    assert _queued(worker_manager) == ["stale"]


@pytest.mark.asyncio
async def test_a_scan_still_receiving_results_is_left_alone(monkeypatch):
    worker_manager = await _run(monkeypatch, _pending_scan("fresh", _WELL_INSIDE))

    assert _queued(worker_manager) == []


@pytest.mark.asyncio
async def test_a_scan_that_reported_nothing_yet_is_left_alone(monkeypatch):
    """Aggregating it would publish a completed scan with no findings at all."""
    worker_manager = await _run(
        monkeypatch,
        _pending_scan("no-results", _WELL_PAST, received_results=[]),
        _pending_scan("never-reported", None),
    )

    assert _queued(worker_manager) == []


@pytest.mark.asyncio
async def test_a_scan_that_is_not_pending_is_left_alone(monkeypatch):
    worker_manager = await _run(
        monkeypatch,
        _pending_scan("done", _WELL_PAST, status="completed"),
        _pending_scan("running", _WELL_PAST, status="processing"),
    )

    assert _queued(worker_manager) == []


@pytest.mark.asyncio
async def test_without_a_worker_nothing_is_read_at_all(monkeypatch):
    """The loop passes None when the worker pool is down, and the body swallows every exception,
    so the only observable contract is that it never opens the cursor."""
    get_database = AsyncMock(return_value=FakeDatabase())
    monkeypatch.setattr("app.core.housekeeping.get_database", get_database)

    await trigger_stale_pending_scans(None)

    get_database.assert_not_awaited()
