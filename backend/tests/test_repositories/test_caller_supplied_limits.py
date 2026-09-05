"""Limits a caller has to state, and limits a caller derives from an id list.

Mongo reads ``limit(0)`` as unbounded, so a repository taking ``len(ids)`` as its limit opens a
whole-collection cursor the moment the list is empty; only ``to_list(0)`` keeps the rows out.
"""

import inspect

import pytest

from app.repositories.findings import FindingRepository
from app.repositories.projects import ProjectRepository
from app.repositories.scans import ScanRepository
from tests.mocks.fake_mongo import FakeDatabase

_NOTHING_ASKED_FOR = 0
_SEEDED_DOCUMENTS = 3


def _defaulted(method) -> set[str]:
    return {
        name
        for name, parameter in inspect.signature(method).parameters.items()
        if parameter.default is not inspect.Parameter.empty
    }


@pytest.mark.parametrize(
    "method",
    [FindingRepository.find_by_scan, ScanRepository.find_many_with_stats, ProjectRepository.find_many_with_scan_id],
)
def test_the_caller_has_to_state_the_limit(method):
    assert "limit" not in _defaulted(method)


async def _seeded_projects() -> ProjectRepository:
    db = FakeDatabase()
    for index in range(_SEEDED_DOCUMENTS):
        await db.projects.insert_one({"_id": f"p{index}", "name": f"project-{index}"})
    return ProjectRepository(db)


async def _seeded_scans() -> ScanRepository:
    db = FakeDatabase()
    for index in range(_SEEDED_DOCUMENTS):
        await db.scans.insert_one({"_id": f"s{index}", "project_id": "p0", "branch": "main", "stats": {"critical": 1}})
    return ScanRepository(db)


@pytest.mark.asyncio
async def test_projects_asked_for_nothing_do_not_answer_with_the_collection():
    repo = await _seeded_projects()

    assert await repo.find_many_with_scan_id({}, limit=_NOTHING_ASKED_FOR) == []


@pytest.mark.asyncio
async def test_scans_asked_for_nothing_do_not_answer_with_the_collection():
    repo = await _seeded_scans()

    assert await repo.find_many_with_stats({}, limit=_NOTHING_ASKED_FOR) == []
