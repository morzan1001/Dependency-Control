"""A graph cut at SCAN_DEPENDENCY_READ_LIMIT must say so, or an unread package looks absent from the scan."""

from app.api.v1.endpoints.analytics.dependencies import _build_dependency_graph

_CAP = 4
_POPULATION = 6


def test_the_graph_carries_the_pair_a_reader_needs():
    rows = [
        {
            "_id": f"dep-{i}",
            "name": f"pkg-{i}",
            "version": "1.0.0",
            "purl": f"pkg:pypi/pkg-{i}@1.0.0",
            "locations": [],
        }
        for i in range(_CAP)
    ]

    graph = _build_dependency_graph(rows, {}, _POPULATION)

    assert graph.dependencies_read == _CAP
    assert graph.dependencies_total == _POPULATION
