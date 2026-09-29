"""Changing a project's default branch moves the cached head with it, so the project list and the
dashboard report the same branch the project page does."""

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.api.v1.endpoints.projects import update_project
from app.core.permissions import Permissions
from app.models.project import Project
from app.models.user import User
from app.schemas.project import ProjectUpdate
from tests.mocks.fake_mongo import FakeDatabase

MODULE = "app.api.v1.endpoints.projects"
_T0 = datetime(2026, 9, 1, tzinfo=timezone.utc)
_DEVELOP_CRITICALS = 5


async def _put(db: FakeDatabase, project: Project, **body):
    user = User(id="u-1", username="admin", email="admin@test.com", permissions=[Permissions.PROJECT_UPDATE])
    with (
        patch(f"{MODULE}.check_project_access", AsyncMock(return_value=project)),
        patch(
            f"{MODULE}.deps.get_system_settings",
            AsyncMock(return_value=MagicMock(retention_mode=None, rescan_mode=None)),
        ),
        patch(f"{MODULE}._audit_license_policy_change", AsyncMock()),
    ):
        return await update_project(project.id, ProjectUpdate(**body), user, db)


async def _seeded(project: Project) -> FakeDatabase:
    db = FakeDatabase()
    await db.projects.insert_one(project.model_dump(by_alias=True))
    await db.scans.insert_one(
        {
            "_id": "s-main",
            "project_id": project.id,
            "branch": "main",
            "status": "completed",
            "created_at": _T0,
            "stats": {"critical": 0},
        }
    )
    await db.scans.insert_one(
        {
            "_id": "s-develop",
            "project_id": project.id,
            "branch": "develop",
            "status": "completed",
            "created_at": _T0 - timedelta(days=3),
            "stats": {"critical": _DEVELOP_CRITICALS},
        }
    )
    return db


@pytest.mark.asyncio
async def test_a_new_default_branch_moves_the_cached_head_and_its_stats():
    project = Project(id="p-1", name="demo", default_branch="main", latest_scan_id="s-main", stats={"critical": 0})
    db = await _seeded(project)

    updated = await _put(db, project, default_branch="develop")

    assert updated.latest_scan_id == "s-develop"
    stored = await db.projects.find_one({"_id": "p-1"})
    assert stored["stats"]["critical"] == _DEVELOP_CRITICALS


@pytest.mark.asyncio
async def test_an_unchanged_default_branch_leaves_the_head_alone():
    project = Project(id="p-1", name="demo", default_branch="main", latest_scan_id="s-main")
    db = await _seeded(project)

    updated = await _put(db, project, name="renamed")

    assert updated.latest_scan_id == "s-main"
