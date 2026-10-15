"""A graph cut at SCAN_DEPENDENCY_READ_LIMIT must say so, or an unread package looks absent from the scan."""

import pytest

from app.api.v1.endpoints.analytics.dependencies import _build_dependency_graph
from app.models.dependency import Dependency
from app.repositories.dependencies import DependencyRepository

_PROJECT = "p1"
_SCAN = "s1"
_CAP = 4
_POPULATION = 6


def _seed(db, count: int) -> None:
    for index in range(count):
        doc = {
            "_id": f"dep-{index}",
            "scan_id": _SCAN,
            "project_id": _PROJECT,
            "name": f"pkg-{index}",
            "version": "1.0.0",
            "purl": f"pkg:pypi/pkg-{index}@1.0.0",
        }
        db.dependencies._docs[doc["_id"]] = doc


@pytest.mark.asyncio
async def test_a_saturated_read_reports_what_the_scan_holds(db):
    _seed(db, _POPULATION)

    rows, total = await DependencyRepository(db).find_by_scan(_PROJECT, _SCAN, limit=_CAP)

    assert len(rows) == _CAP
    assert total == _POPULATION


@pytest.mark.asyncio
async def test_an_unsaturated_read_counts_what_it_read(db):
    _seed(db, _CAP - 1)

    rows, total = await DependencyRepository(db).find_by_scan(_PROJECT, _SCAN, limit=_CAP)

    assert len(rows) == _CAP - 1
    assert total == _CAP - 1


def test_the_graph_carries_the_pair_a_reader_needs():
    deps = [
        Dependency(project_id=_PROJECT, scan_id=_SCAN, name=f"pkg-{i}", version="1.0.0", purl=f"pkg:pypi/pkg-{i}@1.0.0")
        for i in range(_CAP)
    ]

    graph = _build_dependency_graph(deps, {}, _POPULATION)

    assert graph.dependencies_read == _CAP
    assert graph.dependencies_total == _POPULATION
