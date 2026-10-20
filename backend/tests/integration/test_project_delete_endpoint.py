"""Deleting a project takes every scan with it, and a repeated request finds nothing left to delete."""

import pytest

from tests.helpers.databases import DATABASES

pytestmark = pytest.mark.asyncio


@pytest.mark.parametrize("database", DATABASES)
async def test_a_deleted_project_leaves_no_scan_and_a_retry_is_not_found(
    client, db, database, owner_auth_headers_proj, monkeypatch
):
    from app.api.v1.endpoints import projects

    monkeypatch.setattr(projects, "ARCHIVE_BATCH_SIZE", 2)
    await db.scans.insert_many([{"_id": f"s-{i}", "project_id": "p", "status": "completed"} for i in range(5)])
    await db.findings.insert_many([{"_id": f"f-{i}", "scan_id": f"s-{i}"} for i in range(5)])
    await db.scans.insert_one({"_id": "other", "project_id": "p2", "status": "completed"})

    first = await client.delete("/api/v1/projects/p", headers=owner_auth_headers_proj)
    retry = await client.delete("/api/v1/projects/p", headers=owner_auth_headers_proj)

    assert (first.status_code, retry.status_code) == (204, 404)
    assert [doc["_id"] async for doc in db.scans.find({})] == ["other"]
    assert await db.findings.count_documents({}) == 0
