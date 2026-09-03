"""A release row outlives the scan it points at unless the project delete takes it too."""

from unittest.mock import AsyncMock, patch

import pytest

from app.models.project import Project
from app.models.user import User
from tests.mocks.fake_mongo import FakeDatabase

ENDPOINTS = "app.api.v1.endpoints.projects"

_DELETED_PROJECT = "proj-1"
_SURVIVING_PROJECT = "proj-2"
_PRODUCTION = "production"


def _release(project_id: str, scan_id: str) -> dict:
    return {
        "_id": f"row-{project_id}",
        "project_id": project_id,
        "environment": _PRODUCTION,
        "scan_id": scan_id,
    }


@pytest.mark.asyncio
async def test_delete_project_deletes_its_releases():
    from app.api.v1.endpoints.projects import delete_project

    db = FakeDatabase()
    await db.scans.insert_one({"_id": "scan-1", "project_id": _DELETED_PROJECT, "status": "completed", "sbom_refs": []})
    await db.releases.insert_one(_release(_DELETED_PROJECT, "scan-1"))
    await db.releases.insert_one(_release(_SURVIVING_PROJECT, "scan-other"))

    user = User(id="u1", username="u1", email="u1@test.com")
    with patch(f"{ENDPOINTS}.check_project_access", AsyncMock(return_value=Project(id=_DELETED_PROJECT, name="Test"))):
        await delete_project(_DELETED_PROJECT, user, db)

    assert await db.releases.find_one({"project_id": _DELETED_PROJECT}) is None
    assert await db.releases.find_one({"project_id": _SURVIVING_PROJECT}) is not None
