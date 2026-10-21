"""A project deletion removes the project first, then its scans in bounded batches until none are left."""

from unittest.mock import AsyncMock, patch

import pytest

from app.api.v1.endpoints import projects as endpoints
from app.models.project import Project
from app.models.user import User
from app.services.scan_cascade import delete_scans_and_related_data
from tests.mocks.fake_mongo import FakeDatabase

_PROJECT = "proj-1"
_USER = User(id="u1", username="u1", email="u1@test.com")


async def _seed(db: FakeDatabase, scans: int) -> None:
    await db.projects.insert_one({"_id": _PROJECT, "name": "doomed"})
    for i in range(scans):
        await db.scans.insert_one({"_id": f"scan-{i}", "project_id": _PROJECT, "status": "completed"})
        await db.findings.insert_one({"_id": f"finding-{i}", "scan_id": f"scan-{i}"})


async def _delete(db: FakeDatabase, cascade) -> None:
    with (
        patch(f"{endpoints.__name__}.check_project_access", AsyncMock(return_value=Project(id=_PROJECT, name="x"))),
        patch(f"{endpoints.__name__}.delete_scans_and_related_data", cascade),
    ):
        await endpoints.delete_project(_PROJECT, _USER, db)


@pytest.mark.asyncio
async def test_the_project_is_gone_before_its_scans_are_removed():
    """Ingest resolves the project by key or binding, so it can no longer add a scan once the cascade runs."""
    db = FakeDatabase()
    await _seed(db, 1)
    project_at_cascade = []

    async def cascade(db_, scan_ids, label=""):
        project_at_cascade.append(await db.projects.find_one({"_id": _PROJECT}))
        return await delete_scans_and_related_data(db_, scan_ids, label)

    await _delete(db, cascade)

    assert project_at_cascade == [None]


@pytest.mark.asyncio
async def test_a_scan_ingested_during_the_cascade_is_removed_too():
    db = FakeDatabase()
    await _seed(db, 1)
    calls = 0

    async def cascade_racing_an_ingest(db_, scan_ids, label=""):
        nonlocal calls
        calls += 1
        if calls == 1:
            await db.scans.insert_one({"_id": "late", "project_id": _PROJECT, "status": "pending"})
            await db.findings.insert_one({"_id": "late-finding", "scan_id": "late"})
        return await delete_scans_and_related_data(db_, scan_ids, label)

    await _delete(db, cascade_racing_an_ingest)

    assert await db.scans.count_documents({"project_id": _PROJECT}) == 0
    assert await db.findings.count_documents({}) == 0


@pytest.mark.asyncio
async def test_the_scans_are_removed_in_bounded_batches(monkeypatch):
    monkeypatch.setattr(endpoints, "ARCHIVE_BATCH_SIZE", 2)
    db = FakeDatabase()
    await _seed(db, 5)
    batches = []

    async def recording_cascade(db_, scan_ids, label=""):
        batches.append(len(scan_ids))
        return await delete_scans_and_related_data(db_, scan_ids, label)

    await _delete(db, recording_cascade)

    assert batches == [2, 2, 1]
    assert await db.scans.count_documents({}) == 0
    assert await db.findings.count_documents({}) == 0
