"""Pages sorted on a column many rows share repeat and skip rows unless a unique key breaks the tie."""

from unittest.mock import AsyncMock, patch

import pytest

from app.api.v1.endpoints.projects import read_project_scans
from app.models.user import User
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
