"""Deleting a project must take the update-frequency rollups of all its scans with it."""

from unittest.mock import AsyncMock, patch

import pytest

from app.models.project import Project
from app.models.user import User
from tests.mocks.fake_mongo import FakeDatabase

ENDPOINTS = "app.api.v1.endpoints.projects"


async def _seed_scan(db: FakeDatabase, project_id: str, scan_id: str) -> None:
    await db.scans.insert_one({"_id": scan_id, "project_id": project_id, "status": "completed", "sbom_refs": []})
    await db.dependencies.insert_one({"_id": f"{scan_id}:d", "scan_id": scan_id, "name": "flask"})
    await db.scan_update_deltas.insert_one({"_id": scan_id, "project_id": project_id, "branch": "main"})
    await db.scan_outdated_sets.insert_one({"_id": scan_id, "names": ["flask"], "n": 1})


@pytest.mark.asyncio
async def test_delete_project_deletes_the_rollups_of_its_scans():
    from app.api.v1.endpoints.projects import delete_project

    db = FakeDatabase()
    await _seed_scan(db, "proj-1", "scan-1")
    await _seed_scan(db, "proj-1", "scan-2")
    await _seed_scan(db, "proj-2", "scan-other")

    user = User(id="u1", username="u1", email="u1@test.com")
    with patch(f"{ENDPOINTS}.check_project_access", AsyncMock(return_value=Project(id="proj-1", name="Test"))):
        await delete_project("proj-1", user, db)

    assert await db.scan_update_deltas.find_one({"_id": "scan-1"}) is None
    assert await db.scan_update_deltas.find_one({"_id": "scan-2"}) is None
    assert await db.scan_outdated_sets.find_one({"_id": "scan-1"}) is None
    assert await db.scan_outdated_sets.find_one({"_id": "scan-2"}) is None
    assert await db.scan_update_deltas.find_one({"_id": "scan-other"}) is not None
    assert await db.scan_outdated_sets.find_one({"_id": "scan-other"}) is not None
