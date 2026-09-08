"""Branch tips: one row per branch of a project, counted and picked over every scan it holds.

The tip is the head rule of ``app/repositories/scans.py`` scoped to one branch — the branch's
newest build, resolved to the freshest analysis of it — so the project tile and the analytics
page report one set of numbers.
"""

from datetime import datetime, timedelta, timezone

import pytest

from app.core.constants import SCAN_STATUS_FAILED, SCAN_STATUS_PENDING
from app.repositories.scans import ScanRepository
from tests.mocks.fake_mongo import FakeDatabase

_NOW = datetime(2026, 9, 1, 12, 0, tzinfo=timezone.utc)
_PROJECT = "p1"
_MAIN = "main"
_RELEASE_BRANCH = "release/2.0"
# More scans than any page of the scan list can return.
_BUSY_BRANCH_SCANS = 120


def _scan(scan_id: str, branch: str, hours_old: int, **overrides) -> dict:
    doc: dict = {
        "_id": scan_id,
        "project_id": _PROJECT,
        "branch": branch,
        "status": "completed",
        "is_rescan": False,
        "created_at": _NOW - timedelta(hours=hours_old),
    }
    doc.update(overrides)
    return doc


async def _seeded(scans: list[dict]) -> FakeDatabase:
    db = FakeDatabase()
    for scan in scans:
        await db.scans.insert_one(scan)
    # Both rescan creators stamp the forward link on the source as they insert the rescan.
    for scan in scans:
        if scan.get("original_scan_id"):
            await db.scans.update_one({"_id": scan["original_scan_id"]}, {"$set": {"latest_rescan_id": scan["_id"]}})
    return db


@pytest.mark.asyncio
async def test_a_branch_older_than_a_whole_page_of_another_still_gets_a_row():
    scans = [_scan(f"m{i:04d}", _MAIN, i) for i in range(_BUSY_BRANCH_SCANS)]
    scans.append(_scan("r1", _RELEASE_BRANCH, _BUSY_BRANCH_SCANS + 10))
    repo = ScanRepository(await _seeded(scans))

    tips = await repo.branch_tips(_PROJECT)

    assert [branch for branch, _count, _tip in tips] == [_MAIN, _RELEASE_BRANCH]


@pytest.mark.asyncio
async def test_scan_count_covers_the_branch_rather_than_a_page_of_it():
    scans = [_scan(f"m{i:04d}", _MAIN, i) for i in range(_BUSY_BRANCH_SCANS)]
    repo = ScanRepository(await _seeded(scans))

    tips = await repo.branch_tips(_PROJECT)

    assert tips[0][1] == _BUSY_BRANCH_SCANS


@pytest.mark.asyncio
async def test_rescans_are_left_out_of_the_count():
    repo = ScanRepository(await _seeded([_scan("m1", _MAIN, 2), _scan("m2", _MAIN, 1, is_rescan=True)]))

    tips = await repo.branch_tips(_PROJECT)

    assert tips[0][1] == 1


@pytest.mark.asyncio
async def test_a_rescan_of_an_older_commit_does_not_become_the_tip():
    repo = ScanRepository(
        await _seeded(
            [
                _scan("older", _MAIN, 100),
                _scan("tip", _MAIN, 24),
                _scan("rescan", _MAIN, 1, is_rescan=True, original_scan_id="older"),
            ]
        )
    )

    _branch, _count, tip = (await repo.branch_tips(_PROJECT))[0]

    assert tip is not None
    assert tip["_id"] == "tip"


@pytest.mark.asyncio
async def test_the_tip_is_the_freshest_analysis_of_the_newest_build():
    """The tile reads the tip's stats, so demoting the rescan here would show the project one set
    of numbers while the analytics page shows another."""
    repo = ScanRepository(
        await _seeded([_scan("tip", _MAIN, 24), _scan("rescan", _MAIN, 1, is_rescan=True, original_scan_id="tip")])
    )

    _branch, _count, tip = (await repo.branch_tips(_PROJECT))[0]

    assert tip is not None
    assert tip["_id"] == "rescan"


@pytest.mark.asyncio
async def test_a_rescan_is_the_tip_when_the_branch_holds_nothing_built():
    repo = ScanRepository(await _seeded([_scan("rescan", _MAIN, 1, is_rescan=True)]))

    _branch, _count, tip = (await repo.branch_tips(_PROJECT))[0]

    assert tip is not None
    assert tip["_id"] == "rescan"


@pytest.mark.asyncio
async def test_a_branch_whose_scans_all_failed_is_listed_without_a_tip():
    repo = ScanRepository(await _seeded([_scan("m1", _MAIN, 1, status=SCAN_STATUS_FAILED)]))

    branch, count, tip = (await repo.branch_tips(_PROJECT))[0]

    assert (branch, count, tip) == (_MAIN, 1, None)


@pytest.mark.asyncio
async def test_deleted_branches_are_excluded():
    repo = ScanRepository(await _seeded([_scan("m1", _MAIN, 1), _scan("r1", _RELEASE_BRANCH, 1)]))

    tips = await repo.branch_tips(_PROJECT, [_RELEASE_BRANCH])

    assert [branch for branch, _count, _tip in tips] == [_MAIN]


@pytest.mark.asyncio
@pytest.mark.parametrize("unusable_status", [SCAN_STATUS_FAILED, SCAN_STATUS_PENDING])
async def test_a_newer_unusable_build_does_not_displace_the_last_good_one(unusable_status):
    scans = [_scan("good", _MAIN, 5), _scan("newer", _MAIN, 1, status=unusable_status)]
    repo = ScanRepository(await _seeded(scans))

    branch, count, tip = (await repo.branch_tips(_PROJECT))[0]

    assert (branch, count) == (_MAIN, 2)
    assert tip is not None and tip["_id"] == "good"
