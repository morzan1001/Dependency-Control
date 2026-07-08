"""Unit tests for _build_dependency_tree, the hierarchical dependency-tree assembler."""

from app.api.v1.endpoints.analytics.dependencies import _build_dependency_tree


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


class TestDependencyTreeBuilder:
    def test_direct_dep_nests_its_transitive_child(self):
        a = _dep("a", direct=True)
        b = _dep("b", parents=[a["purl"]])

        tree = _build_dependency_tree([a, b], {})

        assert len(tree) == 1, "child must nest under its parent, not appear at top level"
        root = tree[0]
        assert root.name == "a"
        assert [c.name for c in root.children] == ["b"]

    def test_transitive_shared_by_two_parents_is_duplicated(self):
        a = _dep("a", direct=True)
        c = _dep("c", direct=True)
        b = _dep("b", parents=[a["purl"], c["purl"]])

        tree = _build_dependency_tree([a, c, b], {})

        assert len(tree) == 2
        by_name = {n.name: n for n in tree}
        assert [child.name for child in by_name["a"].children] == ["b"]
        assert [child.name for child in by_name["c"].children] == ["b"]

    def test_cycle_between_two_packages_terminates(self):
        # a -> b -> a. The builder must not recurse forever.
        a = _dep("a", direct=True, parents=["pkg:pypi/b@1.0.0"])
        b = _dep("b", parents=["pkg:pypi/a@1.0.0"])

        tree = _build_dependency_tree([a, b], {})

        assert len(tree) == 1
        root = tree[0]
        assert root.name == "a"
        assert [c.name for c in root.children] == ["b"]
        # The cycle back to a is dropped rather than expanded again.
        assert root.children[0].children == []

    def test_transitive_with_unresolved_parent_stays_visible_as_orphan(self):
        a = _dep("a", direct=True)
        b = _dep("b", parents=["pkg:npm/does-not-exist@9.9.9"])

        tree = _build_dependency_tree([a, b], {})

        names = {n.name for n in tree}
        assert names == {"a", "b"}
        orphan = next(n for n in tree if n.name == "b")
        assert orphan.direct is False
        assert orphan.children == []

    def test_sbom_without_graph_keeps_all_as_flat_inferred_roots(self):
        deps = [_dep(n, direct=True, direct_inferred=True) for n in ("a", "b", "c")]

        tree = _build_dependency_tree(deps, {})

        assert len(tree) == 3
        assert all(n.direct_inferred for n in tree)
        assert all(n.children == [] for n in tree)

    def test_findings_are_mapped_onto_nodes(self):
        a = _dep("a", direct=True)
        findings_map = {"a": _findings(total=3, critical=1, high=2)}

        tree = _build_dependency_tree([a], findings_map)

        root = tree[0]
        assert root.has_findings is True
        assert root.findings_count == 3
        assert root.findings_severity.critical == 1
        assert root.findings_severity.high == 2

    def test_roots_sorted_by_findings_count_desc(self):
        low = _dep("low", direct=True)
        high = _dep("high", direct=True)
        findings_map = {"low": _findings(total=1), "high": _findings(total=5)}

        tree = _build_dependency_tree([low, high], findings_map)

        assert [n.name for n in tree] == ["high", "low"]

    def test_nested_transitive_is_not_also_listed_as_orphan(self):
        a = _dep("a", direct=True)
        b = _dep("b", parents=[a["purl"]])
        c = _dep("c", parents=[b["purl"]])

        tree = _build_dependency_tree([a, b, c], {})

        assert len(tree) == 1
        root = tree[0]
        assert [child.name for child in root.children] == ["b"]
        assert [grandchild.name for grandchild in root.children[0].children] == ["c"]

    def test_orphan_child_nests_under_resolvable_orphan_parent(self):
        # b's parent is an unresolvable ref, but c's parent (b) IS a node -> c must nest
        # under b, not appear as a second flat "not linked to a parent" sibling.
        a = _dep("a", direct=True)
        b = _dep("b", parents=["pkg:npm/native-ref@0.0.0"])
        c = _dep("c", parents=[b["purl"]])

        tree = _build_dependency_tree([a, b, c], {})

        assert {n.name for n in tree} == {"a", "b"}
        b_node = next(n for n in tree if n.name == "b")
        assert [child.name for child in b_node.children] == ["c"]

    def test_graph_with_no_direct_deps_still_nests(self):
        # A CycloneDX cycle graph can resolve zero direct deps; nesting must not collapse to flat.
        a = _dep("a")
        b = _dep("b", parents=[a["purl"]])

        tree = _build_dependency_tree([a, b], {})

        assert [n.name for n in tree] == ["a"]
        assert [child.name for child in tree[0].children] == ["b"]

    def test_purl_less_deps_get_distinct_ids(self):
        # SPDX packages without a PURL must still get unique node ids (from the document id),
        # otherwise the frontend dedups distinct packages into one and miscounts.
        a = {"id": "uuid-a", "name": "a", "version": "1", "type": "pypi", "direct": True, "parent_components": []}
        b = {"id": "uuid-b", "name": "b", "version": "1", "type": "pypi", "direct": True, "parent_components": []}

        tree = _build_dependency_tree([a, b], {})

        assert sorted(n.id for n in tree) == ["uuid-a", "uuid-b"]

    def test_cap_bounds_nested_expansion_without_dropping_deps(self, monkeypatch):
        from app.api.v1.endpoints.analytics import dependencies as deps_mod

        monkeypatch.setattr(deps_mod, "_MAX_TREE_NODES", 3)
        a = _dep("a", direct=True)
        b = _dep("b", parents=[a["purl"]])
        c = _dep("c", parents=[b["purl"]])
        d = _dep("d", parents=[c["purl"]])
        e = _dep("e", parents=[d["purl"]])

        tree = deps_mod._build_dependency_tree([a, b, c, d, e], {})

        def node_count(node):
            return 1 + sum(node_count(ch) for ch in node.children)

        root = next(n for n in tree if n.name == "a")
        assert node_count(root) == 3  # nested chain truncated at the cap

        seen = set()

        def collect(nodes):
            for n in nodes:
                seen.add(n.name)
                collect(n.children)

        collect(tree)
        assert seen == {"a", "b", "c", "d", "e"}  # deps cut by the cap resurface as orphans

    def test_findings_absent_yields_no_severity(self):
        a = _dep("a", direct=True)

        node = _build_dependency_tree([a], {})[0]

        assert node.has_findings is False
        assert node.findings_count == 0
        assert node.findings_severity is None

    def test_children_sorted_by_findings_count_desc(self):
        a = _dep("a", direct=True)
        low = _dep("low", parents=[a["purl"]])
        high = _dep("high", parents=[a["purl"]])
        findings_map = {"low": _findings(total=1), "high": _findings(total=9)}

        root = _build_dependency_tree([a, low, high], findings_map)[0]

        assert [c.name for c in root.children] == ["high", "low"]

    def test_three_node_cycle_terminates(self):
        a = _dep("a", direct=True, parents=["pkg:pypi/c@1.0.0"])
        b = _dep("b", parents=[a["purl"]])
        c = _dep("c", parents=[b["purl"]])

        tree = _build_dependency_tree([a, b, c], {})

        assert len(tree) == 1
        root = tree[0]
        assert [x.name for x in root.children] == ["b"]
        assert [x.name for x in root.children[0].children] == ["c"]
        assert root.children[0].children[0].children == []  # cycle edge back to a is dropped

    def test_direct_dep_also_pulled_by_another_direct_dep(self):
        a = _dep("a", direct=True)
        b = _dep("b", direct=True, parents=[a["purl"]])

        tree = _build_dependency_tree([a, b], {})

        names = [n.name for n in tree]
        assert names.count("a") == 1 and names.count("b") == 1
        a_node = next(n for n in tree if n.name == "a")
        assert [c.name for c in a_node.children] == ["b"]
