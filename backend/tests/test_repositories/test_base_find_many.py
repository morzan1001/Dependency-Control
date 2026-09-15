"""BaseRepository.find_many treats its limit as a caller budget, and pymongo reads limit(0) as
unbounded, so the floor is what keeps a zero budget from meaning "the whole collection"."""

import asyncio

from app.repositories.dependencies import DependencyRepository
from tests.mocks.fake_mongo import FakeDatabase

_POPULATION = 5


def _seeded() -> FakeDatabase:
    db = FakeDatabase()
    for index in range(_POPULATION):
        db.dependencies._docs[f"dep-{index}"] = {
            "_id": f"dep-{index}",
            "project_id": "p1",
            "scan_id": "s1",
            "name": f"pkg-{index}",
            "version": "1.0.0",
        }
    return db


def test_a_limit_of_zero_still_reads_one_document():
    repo = DependencyRepository(_seeded())

    found = asyncio.run(repo.find_many({}, limit=0))

    assert len(found) == 1


def test_a_positive_limit_is_passed_through_untouched():
    repo = DependencyRepository(_seeded())

    found = asyncio.run(repo.find_many({}, limit=3))

    assert len(found) == 3
