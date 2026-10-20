"""The daily stale-metadata pass must read only restored scans, a handful among every scan and archive."""

from datetime import datetime, timedelta, timezone

import pytest

from app.core.init_db import create_indexes
from app.models.project import Scan
from app.services.archive import reap_stale_metadata

pytestmark = [pytest.mark.asyncio, pytest.mark.live_mongo]

_ARCHIVED_AT = datetime(2026, 9, 1, tzinfo=timezone.utc)
_SCANS = 60
_RESTORED = 3
_GONE = 40


def _metadata(scan_id: str) -> dict:
    return {"_id": f"meta-{scan_id}", "scan_id": scan_id, "project_id": "p1", "archived_at": _ARCHIVED_AT}


async def _reads(db, collection: str) -> list[dict]:
    return await db["system.profile"].find({"ns": f"{db.name}.{collection}", "op": "query"}).to_list(None)


async def test_the_stale_metadata_pass_reads_only_restored_scans_and_their_metadata(db):
    await create_indexes(db)
    live = [Scan(project_id="p1", branch="main").model_dump(by_alias=True) for _ in range(_SCANS)]
    restored = [
        {"_id": f"restored-{n}", "project_id": "p1", "restored_at": _ARCHIVED_AT + timedelta(days=1)}
        for n in range(_RESTORED)
    ]
    await db.scans.insert_many([*live, *restored])
    await db.archive_metadata.insert_many(
        [_metadata(scan["_id"]) for scan in restored] + [_metadata(f"gone-{n}") for n in range(_GONE)]
    )

    await db.command("profile", 2)
    reaped = await reap_stale_metadata(db)
    await db.command("profile", 0)

    assert reaped == _RESTORED
    assert [read["docsExamined"] for read in await _reads(db, "scans")] == [_RESTORED]
    assert [read["docsExamined"] for read in await _reads(db, "archive_metadata")] == [_RESTORED]
    assert await db.archive_metadata.count_documents({}) == _GONE
