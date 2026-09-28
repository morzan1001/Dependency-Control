import pytest

from app.repositories.dependencies import DependencyRepository
from app.services.update_frequency import DEP_PROJECTION, load_scan_deps
from tests.mocks.fake_mongo import FakeDatabase


async def _seeded() -> DependencyRepository:
    db = FakeDatabase()
    await db.dependencies.insert_one(
        {"_id": "d1", "project_id": "p1", "scan_id": "s1", "name": "left-pad", "version": "1.0.0", "type": "npm"}
    )
    await db.dependencies.insert_one(
        {"_id": "d2", "project_id": "p1", "scan_id": "s2", "name": "left-pad", "version": "2.0.0", "type": "npm"}
    )
    return DependencyRepository(db)


@pytest.mark.asyncio
async def test_a_scans_raw_dependencies_are_read_by_its_id_alone():
    repo = await _seeded()

    rows = await repo.find_raw_by_scan("s1", {"version": 1})

    assert rows == [{"_id": "d1", "version": "1.0.0"}]


@pytest.mark.asyncio
async def test_the_scan_dependencies_fold_by_identity():
    repo = await _seeded()

    folded = await load_scan_deps(repo, "s2")

    assert [info["version"] for info in folded.values()] == ["2.0.0"]
    assert set(DEP_PROJECTION) <= {"name", "version", "type", "purl"}
