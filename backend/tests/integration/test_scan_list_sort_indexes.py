"""The scan lists page off an index whose keys end in the sort's _id tiebreak, so no page blocks on an in-memory sort."""

from datetime import datetime, timedelta, timezone

import pytest

from app.api.v1.endpoints.projects import read_all_scans, read_project_scans
from app.core.init_db import create_indexes
from app.core.permissions import Permissions
from app.models.user import User
from tests.helpers.profiler import profiled

pytestmark = [pytest.mark.asyncio, pytest.mark.live_mongo]

_READER = User(id="r", username="r", email="r@corp.com", permissions=[Permissions.PROJECT_READ_ALL])
_T0 = datetime(2026, 10, 1, tzinfo=timezone.utc)


def _sorted_in_memory(entries: list[dict]) -> list[bool]:
    return [bool(e.get("hasSortStage")) for e in entries if e["ns"].endswith(".scans") and "planSummary" in e]


async def test_no_scan_list_page_needs_an_in_memory_sort(db):
    await create_indexes(db)
    await db.projects.insert_one({"_id": "p", "name": "p", "members": [], "team_ids": []})
    # Same-millisecond pairs: only the _id tiebreak gives them a fixed place across pages.
    await db.scans.insert_many(
        [
            {
                "_id": f"s-{i:02d}",
                "project_id": "p",
                "branch": f"b-{i % 3}",
                "status": ("completed", "failed")[i % 2],
                "pipeline_iid": i // 4,
                "findings_count": i % 5,
                "created_at": _T0 + timedelta(minutes=i // 2),
            }
            for i in range(20)
        ]
    )

    in_memory = {}
    for sort_order in ("asc", "desc"):
        for sort_by in ("created_at", "branch", "status", "pipeline_iid", "findings_count"):
            page = read_project_scans("p", _READER, db, skip=5, limit=5, sort_by=sort_by, sort_order=sort_order)
            scans, entries = await profiled(db, page)
            assert len(scans) == 5
            in_memory[("project", sort_by, sort_order)] = _sorted_in_memory(entries)
        rows, entries = await profiled(db, read_all_scans(_READER, db, limit=5, skip=5, sort_order=sort_order))
        assert len(rows) == 5
        in_memory[("all", "created_at", sort_order)] = _sorted_in_memory(entries)

    assert {key: plans for key, plans in in_memory.items() if plans != [False]} == {}
