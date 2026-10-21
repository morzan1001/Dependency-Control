from app.api.v1.endpoints.analytics.dependencies import _build_dependency_graph, _tree_findings_map


def _graph(dependencies, findings_map):
    """Every case here reads a whole scan, so the row count is the total."""
    return _build_dependency_graph(dependencies, findings_map, len(dependencies))


def _row(_id, name, version, **fields):
    """A dependency as the tree reads it."""
    return {"_id": _id, "name": name, "version": version, "locations": [], **fields}


def _dep(name, version="1.0.0", direct=False, parents=None, direct_inferred=False):
    return _row(
        f"{name}-{version}",
        name,
        version,
        purl=f"pkg:pypi/{name}@{version}",
        type="pypi",
        direct=direct,
        direct_inferred=direct_inferred,
        parent_components=parents or [],
    )


def _findings(critical=0, high=0, medium=0, low=0):
    severities = ["CRITICAL"] * critical + ["HIGH"] * high + ["MEDIUM"] * medium + ["LOW"] * low
    advisories = [{"id": f"CVE-2026-{index:04d}", "severity": sev} for index, sev in enumerate(severities)]
    return {"1.0.0": [{"vulnerabilities": advisories}]}


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

        graph = _graph([a, b], {})

        assert set(_root_names(graph)) == {"a"}
        assert _child_names(graph, _by_name(graph)["a"]) == ["b"]
        assert {n.name for n in graph.nodes} == {"a", "b"}

    def test_shared_transitive_is_a_single_node_under_both_parents(self):
        a = _dep("a", direct=True)
        c = _dep("c", direct=True)
        b = _dep("b", parents=[a["purl"], c["purl"]])

        graph = _graph([a, c, b], {})

        assert set(_root_names(graph)) == {"a", "c"}
        by_name = _by_name(graph)
        assert _child_names(graph, by_name["a"]) == ["b"]
        assert _child_names(graph, by_name["c"]) == ["b"]
        assert sum(1 for n in graph.nodes if n.name == "b") == 1

    def test_two_node_cycle_is_represented_without_recursion(self):
        a = _dep("a", direct=True, parents=["pkg:pypi/b@1.0.0"])
        b = _dep("b", parents=[a["purl"]])

        graph = _graph([a, b], {})

        assert set(_root_names(graph)) == {"a"}
        by_name = _by_name(graph)
        assert _child_names(graph, by_name["a"]) == ["b"]
        assert _child_names(graph, by_name["b"]) == ["a"]  # edge kept; client stops at the ancestor

    def test_fully_disconnected_cycle_stays_reachable(self):
        # a -> b -> c -> a, none direct: no natural root, but nothing may be hidden.
        a = _dep("a", parents=["pkg:pypi/c@1.0.0"])
        b = _dep("b", parents=[a["purl"]])
        c = _dep("c", parents=[b["purl"]])

        graph = _graph([a, b, c], {})

        assert len(graph.roots) == 1  # one entry for the component, not every node
        assert _reachable_ids(graph) == {n.id for n in graph.nodes}

    def test_unresolved_parent_becomes_a_root(self):
        a = _dep("a", direct=True)
        b = _dep("b", parents=["pkg:npm/does-not-exist@9.9.9"])

        graph = _graph([a, b], {})

        assert set(_root_names(graph)) == {"a", "b"}
        orphan = _by_name(graph)["b"]
        assert orphan.direct is False
        assert orphan.child_ids == []

    def test_sbom_without_graph_is_all_flat_inferred_roots(self):
        deps = [_dep(n, direct=True, direct_inferred=True) for n in ("a", "b", "c")]

        graph = _graph(deps, {})

        assert set(_root_names(graph)) == {"a", "b", "c"}
        assert all(n.direct_inferred for n in graph.nodes)
        assert all(n.child_ids == [] for n in graph.nodes)

    def test_findings_are_mapped_onto_nodes(self):
        a = _dep("a", direct=True)

        graph = _graph([a], {"a": _findings(critical=1, high=2)})

        node = _by_name(graph)["a"]
        assert node.has_findings is True
        assert node.findings_count == 3
        assert node.findings_severity.critical == 1
        assert node.findings_severity.high == 2

    def test_roots_sorted_by_findings_count_desc(self):
        low = _dep("low", direct=True)
        high = _dep("high", direct=True)

        graph = _graph([low, high], {"low": _findings(low=1), "high": _findings(low=5)})

        assert _root_names(graph) == ["high", "low"]

    def test_child_ids_sorted_by_findings_count_desc(self):
        a = _dep("a", direct=True)
        low = _dep("low", parents=[a["purl"]])
        high = _dep("high", parents=[a["purl"]])

        graph = _graph([a, low, high], {"low": _findings(low=1), "high": _findings(low=9)})

        assert _child_names(graph, _by_name(graph)["a"]) == ["high", "low"]

    def test_purl_less_deps_get_distinct_ids(self):
        # CycloneDX operating-system components and SPDX packages often carry no purl.
        a = _row("uuid-a", "debian", "12.5", type="operating-system")
        b = _row("uuid-b", "alpine", "3.19", type="operating-system")

        graph = _graph([a, b], {})

        assert sorted(n.id for n in graph.nodes) == ["uuid-a", "uuid-b"]
        assert set(graph.roots) == {"uuid-a", "uuid-b"}
        assert [n.purl for n in graph.nodes] == ["", ""]

    def test_every_node_is_reachable_from_roots(self):
        a = _dep("a", direct=True)
        b = _dep("b", parents=[a["purl"]])
        c = _dep("c", parents=[b["purl"]])
        orphan = _dep("orphan", parents=["pkg:npm/x@9"])

        graph = _graph([a, b, c, orphan], {})

        assert _reachable_ids(graph) == {n.id for n in graph.nodes}
        assert set(_root_names(graph)) == {"a", "orphan"}
        assert _child_names(graph, _by_name(graph)["b"]) == ["c"]

    def test_disconnected_cycle_with_tail_yields_single_root(self):
        # d hangs off the cycle a->b->c->a and, though first in input order, is reachable via a, so it is no root.
        d = _dep("d", parents=["pkg:pypi/a@1.0.0"])
        a = _dep("a", parents=["pkg:pypi/c@1.0.0"])
        b = _dep("b", parents=[a["purl"]])
        c = _dep("c", parents=[b["purl"]])

        graph = _graph([d, a, b, c], {})

        assert len(graph.roots) == 1
        assert "d" not in _root_names(graph)
        assert _reachable_ids(graph) == {n.id for n in graph.nodes}

    def test_duplicate_purl_across_sboms_merges_parent_edges(self):
        # One purl can arrive in several SBOMs with different parents, and every edge must survive the dedup.
        a = _dep("a", direct=True)
        c = _dep("c", direct=True)
        x_from_sbom1 = _dep("x", parents=[a["purl"]])
        x_from_sbom2 = _dep("x", parents=[c["purl"]])

        graph = _graph([a, c, x_from_sbom1, x_from_sbom2], {})

        by_name = _by_name(graph)
        assert sum(1 for n in graph.nodes if n.name == "x") == 1
        assert _child_names(graph, by_name["a"]) == ["x"]
        assert _child_names(graph, by_name["c"]) == ["x"]

    def test_a_node_is_a_root_when_any_of_its_documents_is_direct(self):
        a = _dep("a", direct=True)
        x_transitive = _dep("x", parents=[a["purl"]])
        x_direct = _dep("x", direct=True)

        graph = _graph([a, x_transitive, x_direct], {})

        assert sorted(_root_names(graph)) == ["a", "x"]
        assert _by_name(graph)["x"].direct is True

    def test_every_severity_is_in_the_breakdown_the_count_sums(self):
        advisories = [
            {"id": f"CVE-2024-100{i}", "severity": sev} for i, sev in enumerate(("HIGH", "NEGLIGIBLE", "UNKNOWN"))
        ]
        findings_map = _tree_findings_map({("a", "1.0.0"): [{"vulnerabilities": advisories}]})

        node = _by_name(_graph([_dep("a", direct=True)], findings_map))["a"]

        assert node.findings_severity is not None
        assert (node.findings_severity.high, node.findings_severity.negligible, node.findings_severity.unknown) == (
            1,
            1,
            1,
        )
        assert node.findings_count == sum(node.findings_severity.model_dump().values()) == 3

    def test_a_versionless_finding_covers_the_node_at_any_version(self):
        findings_map = _tree_findings_map(
            {("a", None): [{"vulnerabilities": [{"id": "CVE-2026-0001", "severity": "HIGH"}]}]}
        )

        node = _by_name(_graph([_dep("a", version="2.0.0", direct=True)], findings_map))["a"]

        assert node.findings_count == 1

    def test_findings_absent_yields_no_severity(self):
        node = _by_name(_graph([_dep("a", direct=True)], {}))["a"]

        assert node.has_findings is False
        assert node.findings_count == 0
        assert node.findings_severity is None
