"""Pages sorted on a column many rows share repeat and skip rows unless a unique key breaks the tie."""

from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

import pytest

from app.api.v1.endpoints.projects import read_all_scans, read_project_scans
from app.api.v1.endpoints.releases import list_releases
from app.core.permissions import Permissions
from app.models.user import User
from app.repositories.projects import ProjectRepository
from app.repositories.releases import ReleaseRepository
from app.repositories.scans import ScanRepository
from app.repositories.waivers import WaiverRepository
from tests.mocks.fake_mongo import FakeDatabase
from tests.mocks.mongodb import create_mock_collection, create_mock_db

_USER = User(id="u1", username="u1", email="u1@test.com", permissions=[])


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("sort_by", "sort_order", "expected"),
    [
        ("status", "asc", [("status", 1), ("created_at", -1), ("_id", 1)]),
        ("status", "desc", [("status", -1), ("created_at", 1), ("_id", -1)]),
        ("findings_count", "desc", [("findings_count", -1), ("created_at", -1), ("_id", 1)]),
        ("pipeline_iid", "asc", [("pipeline_iid", 1), ("created_at", -1), ("_id", 1)]),
        ("branch", "asc", [("branch", 1), ("created_at", -1)]),
        ("created_at", "desc", [("created_at", -1)]),
    ],
)
async def test_the_scan_list_breaks_ties_on_an_indexed_key(sort_by, sort_order, expected):
    find = AsyncMock(return_value=[])
    with (
        patch("app.api.v1.endpoints.projects.check_project_access", AsyncMock()),
        patch.object(ScanRepository, "find_many_raw", find),
    ):
        await read_project_scans("p1", _USER, FakeDatabase(), sort_by=sort_by, sort_order=sort_order)

    assert find.await_args.kwargs["sort"] == expected


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("sort_by", "sort_order", "expected"),
    [
        ("status", 1, [("status", 1), ("_id", 1)]),
        ("expiration_date", -1, [("expiration_date", -1), ("_id", 1)]),
        ("_id", -1, [("_id", -1)]),
    ],
)
async def test_the_waiver_list_breaks_ties_on_the_id(sort_by, sort_order, expected):
    waivers = create_mock_collection()
    repo = WaiverRepository(create_mock_db({"waivers": waivers}))

    await repo.find_many({}, skip=0, limit=10, sort_by=sort_by, sort_order=sort_order)

    assert waivers.find.return_value.sort.call_args.args == (expected,)


@pytest.mark.asyncio
@pytest.mark.parametrize("method", ["find_many", "find_many_raw"])
async def test_a_paged_find_breaks_ties_on_the_id(method):
    projects = create_mock_collection()
    repo = ProjectRepository(create_mock_db({"projects": projects}))

    await getattr(repo, method)({}, skip=20, limit=10, sort_by="stats.critical", sort_order=-1)

    assert projects.find.return_value.sort.call_args.args == ([("stats.critical", -1), ("_id", 1)],)


@pytest.mark.asyncio
async def test_the_recent_scans_list_breaks_ties_on_the_id():
    db = FakeDatabase()
    await db.projects.insert_one({"_id": "p1", "name": "p1"})
    aggregate = AsyncMock(return_value=[])
    reader = User(id="u1", username="u1", email="u1@test.com", permissions=[Permissions.PROJECT_READ_ALL])
    with patch.object(ScanRepository, "aggregate", aggregate):
        await read_all_scans(reader, db, sort_by="status", sort_order="asc")

    pipeline = aggregate.await_args.args[0]
    assert {"$sort": {"status": 1, "_id": 1}} in pipeline


@pytest.mark.asyncio
async def test_the_recent_scans_list_covers_the_projects_analytics_resolves():
    aggregate = AsyncMock(return_value=[])
    reader = User(id="u1", username="u1", email="u1@test.com", permissions=[Permissions.PROJECT_READ])
    with (
        patch("app.api.v1.endpoints.projects.get_user_project_ids", AsyncMock(return_value=["p2"])),
        patch.object(ScanRepository, "aggregate", aggregate),
    ):
        await read_all_scans(reader, FakeDatabase(), sort_by="created_at", sort_order="desc")

    assert aggregate.await_args.args[0][0] == {"$match": {"project_id": {"$in": ["p2"]}}}


@pytest.mark.asyncio
async def test_the_release_list_opens_with_the_environments_current_release():
    db = FakeDatabase()
    released_at = datetime(2026, 9, 1, tzinfo=timezone.utc)
    for release_id, scan_id in (("rel-b", "scan-b"), ("rel-a", "scan-a")):
        await db.releases.insert_one(
            {
                "_id": release_id,
                "project_id": "p1",
                "environment": "prod",
                "scan_id": scan_id,
                "released_at": released_at,
            }
        )

    with patch("app.api.v1.endpoints.releases.check_project_access", AsyncMock()):
        page = await list_releases("p1", _USER, db, skip=0, limit=10, environment="prod")

    current = await ReleaseRepository(db).latest_for_environment("p1", "prod")
    assert current is not None
    assert [item.scan_id for item in page.items] == [current["scan_id"], "scan-b"]
    assert (page.page, page.size, page.total) == (1, 10, 2)
