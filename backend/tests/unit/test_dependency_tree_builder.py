"""Unit tests for _build_dependency_graph, the flat-nodes + adjacency dependency graph."""

from app.api.v1.endpoints.analytics.dependencies import _build_dependency_graph


def _dep(name, version="1.0.0", direct=False, parents=None, direct_inferred=False):
    return {
        "purl": f"pkg:pypi/{name}@{version}",
        "name": name,
        "version": version,
        "type": "pypi",
        "direct": direct,
        "direct_inferred": direct_inferred,
        "parent_components": parents or [],
    }


def _findings(total=0, critical=0, high=0, medium=0, low=0):
    return {"total": total, "critical": critical, "high": high, "medium": medium, "low": low}


def _by_id(graph):
    return {n.id: n for n in graph.nodes}


def _by_name(graph):
    return {n.name: n for n in graph.nodes}


def _root_names(graph):
    by_id = _by_id(graph)
    return [by_id[r].name for r in graph.roots]


def _child_names(graph, node):
    by_id = _by_id(graph)
    return [by_id[cid].name for cid in node.child_ids]


def _reachable_ids(graph):
    by_id = _by_id(graph)
    seen, stack = set(), list(graph.roots)
    while stack:
        node_id = stack.pop()
        if node_id in seen:
            continue
        seen.add(node_id)
        stack.extend(by_id[node_id].child_ids)
    return seen


class TestDependencyGraphBuilder:
    def test_direct_dep_lists_its_transitive_child(self):
        a = _dep("a", direct=True)
        b = _dep("b", parents=[a["purl"]])

        graph = _build_dependency_graph([a, b], {})

        assert set(_root_names(graph)) == {"a"}
        assert _child_names(graph, _by_name(graph)["a"]) == ["b"]
        assert {n.name for n in graph.nodes} == {"a", "b"}

    def test_shared_transitive_is_a_single_node_under_both_parents(self):
        a = _dep("a", direct=True)
        c = _dep("c", direct=True)
        b = _dep("b", parents=[a["purl"], c["purl"]])

        graph = _build_dependency_graph([a, c, b], {})

        assert set(_root_names(graph)) == {"a", "c"}
        by_name = _by_name(graph)
        assert _child_names(graph, by_name["a"]) == ["b"]
        assert _child_names(graph, by_name["c"]) == ["b"]
        assert sum(1 for n in graph.nodes if n.name == "b") == 1  # b exists exactly once

    def test_two_node_cycle_is_represented_without_recursion(self):
        a = _dep("a", direct=True, parents=["pkg:pypi/b@1.0.0"])
        b = _dep("b", parents=[a["purl"]])

        graph = _build_dependency_graph([a, b], {})

        assert set(_root_names(graph)) == {"a"}
        by_name = _by_name(graph)
        assert _child_names(graph, by_name["a"]) == ["b"]
        assert _child_names(graph, by_name["b"]) == ["a"]  # edge kept; client stops at the ancestor

    def test_fully_disconnected_cycle_stays_reachable(self):
        # a -> b -> c -> a, none direct: no natural root, but nothing may be hidden.
        a = _dep("a", parents=["pkg:pypi/c@1.0.0"])
        b = _dep("b", parents=[a["purl"]])
        c = _dep("c", parents=[b["purl"]])

        graph = _build_dependency_graph([a, b, c], {})

        assert len(graph.roots) >= 1
        assert _reachable_ids(graph) == {n.id for n in graph.nodes}

    def test_unresolved_parent_becomes_a_root(self):
        a = _dep("a", direct=True)
        b = _dep("b", parents=["pkg:npm/does-not-exist@9.9.9"])

        graph = _build_dependency_graph([a, b], {})

        assert set(_root_names(graph)) == {"a", "b"}
        orphan = _by_name(graph)["b"]
        assert orphan.direct is False
        assert orphan.child_ids == []

    def test_sbom_without_graph_is_all_flat_inferred_roots(self):
        deps = [_dep(n, direct=True, direct_inferred=True) for n in ("a", "b", "c")]

        graph = _build_dependency_graph(deps, {})

        assert set(_root_names(graph)) == {"a", "b", "c"}
        assert all(n.direct_inferred for n in graph.nodes)
        assert all(n.child_ids == [] for n in graph.nodes)

    def test_findings_are_mapped_onto_nodes(self):
        a = _dep("a", direct=True)

        graph = _build_dependency_graph([a], {"a": _findings(total=3, critical=1, high=2)})

        node = _by_name(graph)["a"]
        assert node.has_findings is True
        assert node.findings_count == 3
        assert node.findings_severity.critical == 1
        assert node.findings_severity.high == 2

    def test_roots_sorted_by_findings_count_desc(self):
        low = _dep("low", direct=True)
        high = _dep("high", direct=True)

        graph = _build_dependency_graph([low, high], {"low": _findings(total=1), "high": _findings(total=5)})

        assert _root_names(graph) == ["high", "low"]

    def test_child_ids_sorted_by_findings_count_desc(self):
        a = _dep("a", direct=True)
        low = _dep("low", parents=[a["purl"]])
        high = _dep("high", parents=[a["purl"]])

        graph = _build_dependency_graph([a, low, high], {"low": _findings(total=1), "high": _findings(total=9)})

        assert _child_names(graph, _by_name(graph)["a"]) == ["high", "low"]

    def test_purl_less_deps_get_distinct_ids(self):
        # SPDX packages without a PURL must still get unique node ids (from the document id).
        a = {"id": "uuid-a", "name": "a", "version": "1", "type": "pypi", "direct": True, "parent_components": []}
        b = {"id": "uuid-b", "name": "b", "version": "1", "type": "pypi", "direct": True, "parent_components": []}

        graph = _build_dependency_graph([a, b], {})

        assert sorted(n.id for n in graph.nodes) == ["uuid-a", "uuid-b"]
        assert set(graph.roots) == {"uuid-a", "uuid-b"}

    def test_every_node_is_reachable_from_roots(self):
        a = _dep("a", direct=True)
        b = _dep("b", parents=[a["purl"]])
        c = _dep("c", parents=[b["purl"]])
        orphan = _dep("orphan", parents=["pkg:npm/x@9"])

        graph = _build_dependency_graph([a, b, c, orphan], {})

        assert _reachable_ids(graph) == {n.id for n in graph.nodes}
        assert _child_names(graph, _by_name(graph)["b"]) == ["c"]
