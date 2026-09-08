"""``count`` and ``distinct`` answer for the filter they were handed, not for the collection."""

import pytest

from app.repositories.scans import ScanRepository
from tests.mocks.fake_mongo import FakeDatabase

_PROJECT_WITH_THREE = "p1"
_PROJECT_WITH_TWO = "p2"
_PROJECT_WITH_ONE = "p3"
_SCANS_PER_PROJECT = {_PROJECT_WITH_THREE: 3, _PROJECT_WITH_TWO: 2, _PROJECT_WITH_ONE: 1}
_TOTAL_SCANS = sum(_SCANS_PER_PROJECT.values())
_COUNT_LIMIT = 2


async def _seeded_repo() -> ScanRepository:
    db = FakeDatabase()
    for project_id, scan_count in _SCANS_PER_PROJECT.items():
        for index in range(scan_count):
            await db.scans.insert_one({"_id": f"{project_id}-{index}", "project_id": project_id, "branch": "main"})
    return ScanRepository(db)


@pytest.mark.asyncio
async def test_count_applies_the_filter():
    repo = await _seeded_repo()

    assert await repo.count({"project_id": _PROJECT_WITH_THREE}) == _SCANS_PER_PROJECT[_PROJECT_WITH_THREE]


@pytest.mark.asyncio
async def test_count_without_a_filter_covers_the_collection():
    repo = await _seeded_repo()

    assert await repo.count() == _TOTAL_SCANS
    assert await repo.count({}) == _TOTAL_SCANS


@pytest.mark.asyncio
async def test_count_caps_at_the_limit_within_the_filter():
    repo = await _seeded_repo()

    assert await repo.count({"project_id": _PROJECT_WITH_THREE}, limit=_COUNT_LIMIT) == _COUNT_LIMIT
    assert await repo.count({"project_id": _PROJECT_WITH_ONE}, limit=_COUNT_LIMIT) == 1


@pytest.mark.asyncio
async def test_distinct_applies_the_filter():
    repo = await _seeded_repo()

    assert await repo.distinct("project_id", {"project_id": _PROJECT_WITH_TWO}) == [_PROJECT_WITH_TWO]
    assert sorted(await repo.distinct("project_id")) == sorted(_SCANS_PER_PROJECT)
