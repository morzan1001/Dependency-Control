"""Housekeeping rescans a branch tip daily, so a lineage outgrows a page while the project's other scans pile up."""

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch

import pytest

from app.api.v1.endpoints.projects import _SCAN_HISTORY_PAGE_SIZE, read_scan_history
from app.core.init_db import create_indexes
from app.models.user import User
from tests.helpers.profiler import profiled

pytestmark = [pytest.mark.asyncio, pytest.mark.live_mongo]

_USER = User(id="u", username="u", email="u@corp.com", permissions=[])
_T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)
_ROOT = "root"
_UNRELATED_SCANS = 400


async def _seed(db, rescans: int) -> list[str]:
    await create_indexes(db)
    lineage = [{"_id": _ROOT, "project_id": "p", "branch": "main", "status": "completed", "created_at": _T0}]
    lineage += [
        {
            "_id": f"rescan-{i:03d}",
            "project_id": "p",
            "branch": "main",
            "status": "completed",
            "is_rescan": True,
            "original_scan_id": _ROOT,
            "created_at": _T0 + timedelta(days=i + 1),
        }
        for i in range(rescans)
    ]
    # Same-day builds of the project's other branches, newer than the lineage, which a project-wide walk would read.
    others = [
        {
            "_id": f"other-{i:03d}",
            "project_id": "p",
            "branch": f"b-{i}",
            "status": "completed",
            "created_at": _T0 + timedelta(days=rescans + 1, minutes=i),
        }
        for i in range(_UNRELATED_SCANS)
    ]
    await db.scans.insert_many(lineage + others)
    return [doc["_id"] for doc in sorted(lineage, key=lambda doc: doc["created_at"], reverse=True)]


def _scan_reads(entries: list[dict]) -> list[dict]:
    return [e for e in entries if e["ns"].endswith(".scans") and e["op"] in ("query", "command")]


async def _history(db, scan_id: str = _ROOT):
    with patch("app.api.v1.endpoints.projects.check_project_access", AsyncMock()):
        return await profiled(db, read_scan_history("p", scan_id, _USER, db))


async def test_a_long_lineage_pages_newest_first_off_the_index_and_counts_the_whole_lineage(db):
    newest_first = await _seed(db, rescans=_SCAN_HISTORY_PAGE_SIZE + 40)

    history, entries = await _history(db, scan_id="rescan-007")

    assert [run.id for run in history.runs] == newest_first[:_SCAN_HISTORY_PAGE_SIZE]
    assert (history.total, history.page_size) == (_SCAN_HISTORY_PAGE_SIZE + 41, _SCAN_HISTORY_PAGE_SIZE)
    reads = _scan_reads(entries)
    assert [e for e in reads if e.get("hasSortStage")] == []
    assert sum(e.get("docsExamined", 0) for e in reads) <= _SCAN_HISTORY_PAGE_SIZE + 2


async def test_a_lineage_within_one_page_is_read_once_and_ends_on_the_original(db):
    newest_first = await _seed(db, rescans=3)

    history, entries = await _history(db)

    assert [run.id for run in history.runs] == newest_first
    assert newest_first[-1] == _ROOT
    assert history.total == 4
    # The scan itself, then its rescans; a lineage that fits the page needs no count.
    assert len(_scan_reads(entries)) == 2
