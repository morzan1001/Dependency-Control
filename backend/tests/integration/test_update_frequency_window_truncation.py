"""The live update-frequency walk names a scan cap only when it left part of the requested window unread."""

from datetime import datetime, timedelta, timezone

import pytest

from app.core.constants import SCAN_STATUS_COMPLETED
from app.repositories.analysis_results import AnalysisResultRepository
from app.repositories.dependencies import DependencyRepository
from app.repositories.scans import ScanRepository
from app.services.update_frequency import DAYS_PER_MONTH, compute_update_frequency

pytestmark = [pytest.mark.live_mongo, pytest.mark.asyncio]

_PROJECT_ID = "uf-project"
_HARD_LIMIT = 10


async def _insert_scans(db, ages_in_days: list[int]) -> None:
    now = datetime.now(tz=timezone.utc)
    for i, age in enumerate(ages_in_days):
        scan_id = f"scan-{i:03d}"
        await db.scans.insert_one(
            {
                "_id": scan_id,
                "project_id": _PROJECT_ID,
                "branch": "main",
                "status": SCAN_STATUS_COMPLETED,
                "is_rescan": False,
                "commit_hash": f"commit-{i:03d}",
                "created_at": now - timedelta(days=age, minutes=i),
            }
        )
        await db.dependencies.insert_one(
            {
                "scan_id": scan_id,
                "project_id": _PROJECT_ID,
                "name": "requests",
                "version": f"2.{i}.0",
                "purl": f"pkg:pypi/requests@2.{i}.0",
                "type": "library",
            }
        )


async def _metrics(db, *, window_days: int | None, max_scans: int = 20):
    return await compute_update_frequency(
        project_id=_PROJECT_ID,
        project_name="UF Project",
        scan_repo=ScanRepository(db),
        dep_repo=DependencyRepository(db),
        analysis_repo=AnalysisResultRepository(db),
        branch="main",
        max_scans=max_scans,
        window_days=window_days,
        hard_limit=_HARD_LIMIT,
    )


async def test_scans_before_the_window_do_not_mark_a_fully_read_window_as_capped(db):
    await _insert_scans(db, [400 - day for day in range(_HARD_LIMIT)] + [40, 30, 20, 10])

    metrics = await _metrics(db, window_days=90)

    assert metrics.scan_count == 4
    assert metrics.window_scan_cap is None
    assert metrics.updates_per_month == round(metrics.total_updates / (90 / DAYS_PER_MONTH), 2)


async def test_a_window_holding_more_scans_than_the_cap_is_capped(db):
    await _insert_scans(db, [80 - day for day in range(_HARD_LIMIT + 4)])

    metrics = await _metrics(db, window_days=90)

    assert metrics.scan_count == _HARD_LIMIT
    assert metrics.window_scan_cap == _HARD_LIMIT


async def test_the_last_scans_mode_names_no_cap_and_no_monthly_rate_on_a_busy_branch(db):
    await _insert_scans(db, list(range(30, 0, -1)))

    metrics = await _metrics(db, window_days=None, max_scans=2)

    assert metrics.scan_count == 2
    assert metrics.window_scan_cap is None
    assert metrics.updates_per_month is None
