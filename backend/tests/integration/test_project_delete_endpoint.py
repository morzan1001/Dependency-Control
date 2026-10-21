"""Deleting a project takes every scan with it, and a repeated request finds nothing left to delete."""

from datetime import datetime, timedelta, timezone
from functools import partial

import pytest

from app.core.constants import ORPHAN_MIN_AGE_HOURS
from app.core.housekeeping import _reap_orphan_scans
from app.services.scan_cascade import delete_scans_matching
from tests.helpers.databases import DATABASES

pytestmark = pytest.mark.asyncio


@pytest.mark.parametrize("database", DATABASES)
async def test_a_deleted_project_leaves_no_scan_and_a_retry_is_not_found(
    client, db, database, owner_auth_headers_proj, monkeypatch
):
    from app.api.v1.endpoints import projects

    monkeypatch.setattr(projects, "delete_scans_matching", partial(delete_scans_matching, batch_size=2))
    await db.scans.insert_many([{"_id": f"s-{i}", "project_id": "p", "status": "completed"} for i in range(5)])
    await db.findings.insert_many([{"_id": f"f-{i}", "scan_id": f"s-{i}"} for i in range(5)])
    await db.scans.insert_one({"_id": "other", "project_id": "p2", "status": "completed"})

    first = await client.delete("/api/v1/projects/p", headers=owner_auth_headers_proj)
    retry = await client.delete("/api/v1/projects/p", headers=owner_auth_headers_proj)

    assert (first.status_code, retry.status_code) == (204, 404)
    assert [doc["_id"] async for doc in db.scans.find({})] == ["other"]
    assert await db.findings.count_documents({}) == 0


@pytest.mark.parametrize("database", DATABASES)
async def test_housekeeping_finishes_a_delete_whose_cascade_broke_off(db, database):
    """The recent-scans page joins each scan to its project after paging, so a leftover scan shortens a page."""
    now = datetime.now(timezone.utc)
    old = now - timedelta(hours=ORPHAN_MIN_AGE_HOURS * 2)
    await db.projects.insert_one({"_id": "p-live", "name": "live"})
    await db.scans.insert_many(
        [
            {"_id": "live-old", "project_id": "p-live", "created_at": old},
            {"_id": "orphan-old-1", "project_id": "p-gone", "created_at": old},
            {"_id": "orphan-old-2", "project_id": "p-gone", "created_at": old},
            {"_id": "orphan-fresh", "project_id": "p-gone", "created_at": now - timedelta(minutes=1)},
        ]
    )
    await db.findings.insert_many(
        [{"_id": "f-live", "scan_id": "live-old"}, {"_id": "f-orphan", "scan_id": "orphan-old-1"}]
    )

    deleted = await _reap_orphan_scans(db, batch_size=1)

    assert deleted == 2
    assert sorted([doc["_id"] async for doc in db.scans.find({})]) == ["live-old", "orphan-fresh"]
    assert [doc["_id"] async for doc in db.findings.find({})] == ["f-live"]
