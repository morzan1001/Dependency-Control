"""Tests for app.services.recommendation.graph."""

from app.schemas.recommendation import Priority, RecommendationType
from app.services.recommendation.graph import (
    analyze_deep_dependency_chains,
    analyze_duplicate_packages,
)


def _dep(name, version="1.0", purl=None, direct=False, parent_components=None):
    return {
        "name": name,
        "version": version,
        "purl": purl or f"pkg:npm/{name}@{version}",
        "direct": direct,
        "parent_components": parent_components or [],
    }


class TestAnalyzeDeepDependencyChainsEmpty:
    def test_empty_returns_empty(self):
        assert analyze_deep_dependency_chains([]) == []


class TestAnalyzeDeepDependencyChainsShallow:
    def test_direct_deps_no_warning(self):
        deps = [
            _dep("express", version="4.18.0", direct=True),
            _dep("lodash", version="4.17.21", direct=True),
        ]
        result = analyze_deep_dependency_chains(deps, max_dependency_depth=3)
        assert len(result) == 0

    def test_shallow_transitive_no_warning(self):
        # depth 2, well within default max_dependency_depth=8
        parent = _dep("express", version="4.18.0", direct=True)
        child = _dep("body-parser", version="1.20.0", direct=False, parent_components=["pkg:npm/express@4.18.0"])
        result = analyze_deep_dependency_chains([parent, child], max_dependency_depth=8)
        assert len(result) == 0


class TestAnalyzeDeepDependencyChainsDeep:
    def _build_chain(self, length):
        return [
            _dep("pkg-0", version="1.0", direct=True),
            *(
                _dep(f"pkg-{i}", version="1.0", direct=False, parent_components=[f"pkg:npm/pkg-{i - 1}@1.0"])
                for i in range(1, length)
            ),
        ]

    def test_chain_exceeding_max_depth_produces_recommendation(self):
        deps = self._build_chain(5)
        result = analyze_deep_dependency_chains(deps, max_dependency_depth=3)
        deep_recs = [r for r in result if "Deep dependency" in r.title or "max depth" in r.title]
        assert len(deep_recs) == 1

    def test_deep_chain_type(self):
        deps = self._build_chain(5)
        result = analyze_deep_dependency_chains(deps, max_dependency_depth=3)
        deep_recs = [r for r in result if "max depth" in r.title]
        assert deep_recs[0].type == RecommendationType.DEEP_DEPENDENCY_CHAIN

    def test_deep_chain_priority_low(self):
        deps = self._build_chain(5)
        result = analyze_deep_dependency_chains(deps, max_dependency_depth=3)
        deep_recs = [r for r in result if "max depth" in r.title]
        assert deep_recs[0].priority == Priority.LOW

    def test_chain_at_max_depth_no_warning(self):
        # Chain of 3, max_dependency_depth=3 => depth is 3, not > 3
        deps = self._build_chain(3)
        result = analyze_deep_dependency_chains(deps, max_dependency_depth=3)
        deep_recs = [r for r in result if "max depth" in r.title]
        assert len(deep_recs) == 0


class TestAnalyzeDeepDependencyChainsCircular:
    def test_circular_detected(self):
        deps_circular = [
            {
                "name": "pkg-a",
                "version": "1.0",
                "purl": "pkg:npm/pkg-a@1.0",
                "direct": True,
                "parent_components": ["pkg:npm/pkg-b@1.0"],
            },
            {
                "name": "pkg-b",
                "version": "1.0",
                "purl": "pkg:npm/pkg-b@1.0",
                "direct": False,
                "parent_components": ["pkg:npm/pkg-a@1.0"],
            },
        ]
        result = analyze_deep_dependency_chains(deps_circular, max_dependency_depth=8)
        circular_recs = [r for r in result if "Circular" in r.title]
        assert len(circular_recs) == 1

    def test_circular_priority_medium(self):
        deps_circular = [
            {
                "name": "pkg-a",
                "version": "1.0",
                "purl": "pkg:npm/pkg-a@1.0",
                "direct": True,
                "parent_components": ["pkg:npm/pkg-b@1.0"],
            },
            {
                "name": "pkg-b",
                "version": "1.0",
                "purl": "pkg:npm/pkg-b@1.0",
                "direct": False,
                "parent_components": ["pkg:npm/pkg-a@1.0"],
            },
        ]
        result = analyze_deep_dependency_chains(deps_circular, max_dependency_depth=8)
        circular_recs = [r for r in result if "Circular" in r.title]
        assert circular_recs[0].priority == Priority.MEDIUM

    def test_circular_affected_components(self):
        deps_circular = [
            {
                "name": "pkg-a",
                "version": "1.0",
                "purl": "pkg:npm/pkg-a@1.0",
                "direct": True,
                "parent_components": ["pkg:npm/pkg-b@1.0"],
            },
            {
                "name": "pkg-b",
                "version": "1.0",
                "purl": "pkg:npm/pkg-b@1.0",
                "direct": False,
                "parent_components": ["pkg:npm/pkg-a@1.0"],
            },
        ]
        result = analyze_deep_dependency_chains(deps_circular, max_dependency_depth=8)
        circular_recs = [r for r in result if "Circular" in r.title]
        components = circular_recs[0].affected_components
        assert any("pkg-a" in c for c in components)
        assert any("pkg-b" in c for c in components)


class TestAnalyzeDeepDependencyChainsCycleSegment:
    def test_ancestor_not_flagged_as_circular(self):
        # A -> B -> C -> B  (cycle is B<->C; A is a non-cycle ancestor)
        deps = [
            {
                "name": "pkg-a",
                "version": "1.0",
                "purl": "pkg:npm/pkg-a@1.0",
                "direct": True,
                "parent_components": [],
            },
            {
                "name": "pkg-b",
                "version": "1.0",
                "purl": "pkg:npm/pkg-b@1.0",
                "direct": False,
                "parent_components": ["pkg:npm/pkg-a@1.0", "pkg:npm/pkg-c@1.0"],
            },
            {
                "name": "pkg-c",
                "version": "1.0",
                "purl": "pkg:npm/pkg-c@1.0",
                "direct": False,
                "parent_components": ["pkg:npm/pkg-b@1.0"],
            },
        ]
        result = analyze_deep_dependency_chains(deps, max_dependency_depth=8)
        circular_recs = [r for r in result if "Circular" in r.title]
        assert len(circular_recs) == 1
        components = circular_recs[0].affected_components
        assert any("pkg-b" in c for c in components)
        assert any("pkg-c" in c for c in components)
        assert not any("pkg-a" in c for c in components)
        assert circular_recs[0].impact["total"] == 2


class TestAnalyzeDeepDependencyChainsBothCircularAndDeep:
    def test_both_circular_and_deep(self):
        circular_deps = [
            {
                "name": "circ-a",
                "version": "1.0",
                "purl": "pkg:npm/circ-a@1.0",
                "direct": True,
                "parent_components": ["pkg:npm/circ-b@1.0"],
            },
            {
                "name": "circ-b",
                "version": "1.0",
                "purl": "pkg:npm/circ-b@1.0",
                "direct": False,
                "parent_components": ["pkg:npm/circ-a@1.0"],
            },
        ]

        # Deep chain: root -> d1 -> d2 -> d3 -> d4 (depth 5, max_dependency_depth=2)
        deep_chain = [
            _dep("root", version="1.0", direct=True),
            *(
                _dep(
                    f"deep-{i}",
                    version="1.0",
                    direct=False,
                    parent_components=[f"pkg:npm/{'root' if i == 1 else f'deep-{i - 1}'}@1.0"],
                )
                for i in range(1, 5)
            ),
        ]

        all_deps = circular_deps + deep_chain
        result = analyze_deep_dependency_chains(all_deps, max_dependency_depth=2)
        assert len(result) == 2
        titles = [r.title for r in result]
        assert any("Circular" in t for t in titles)
        assert any("max depth" in t.lower() or "deep" in t.lower() for t in titles)


class TestAnalyzeDeepDependencyChainsDepthResolution:
    def test_siblings_under_one_parent_each_get_their_depth(self):
        deps = [
            _dep("root", direct=True),
            _dep("left", parent_components=["pkg:npm/root@1.0"]),
            _dep("right", parent_components=["pkg:npm/root@1.0"]),
        ]
        result = analyze_deep_dependency_chains(deps, max_dependency_depth=1)
        assert len(result) == 1
        assert sorted(result[0].affected_components) == ["left@1.0 (depth: 2)", "right@1.0 (depth: 2)"]

    def test_a_dependency_without_purl_is_keyed_by_name_and_version(self):
        root = {"name": "root", "version": "1.0", "direct": True, "parent_components": []}
        child = {"name": "child", "version": "2.0", "direct": False, "parent_components": ["root@1.0"]}
        result = analyze_deep_dependency_chains([root, child], max_dependency_depth=1)
        assert result[0].affected_components == ["child@2.0 (depth: 2)"]

    def test_depth_resolution_stops_after_ten_passes(self):
        # Listed deepest-first, each pass resolves one more level of the chain.
        chain = [_dep("pkg-0", direct=True)] + [
            _dep(f"pkg-{i}", parent_components=[f"pkg:npm/pkg-{i - 1}@1.0"]) for i in range(1, 13)
        ]
        result = analyze_deep_dependency_chains(list(reversed(chain)), max_dependency_depth=8)
        assert len(result) == 1
        assert result[0].affected_components == [
            "pkg-10@1.0 (depth: 11)",
            "pkg-9@1.0 (depth: 10)",
            "pkg-8@1.0 (depth: 9)",
        ]

    def test_deep_recommendation_splits_impact_at_depth_seven_and_previews_parents(self):
        chain = [_dep("pkg-0", direct=True)] + [
            _dep(f"pkg-{i}", parent_components=[f"pkg:npm/pkg-{i - 1}@1.0", "pkg:npm/pkg-0@1.0"]) for i in range(1, 9)
        ]
        result = analyze_deep_dependency_chains(chain, max_dependency_depth=6)
        assert len(result) == 1
        rec = result[0]
        assert rec.title == "Deep dependency chains detected (max depth: 9)"
        assert rec.impact == {"critical": 0, "high": 0, "medium": 2, "low": 1, "total": 3}
        assert rec.action["deepest_chains"][0] == {
            "package": "pkg-8",
            "depth": 9,
            "chain_preview": "pkg:npm/pkg-7@1.0 → pkg:npm/pkg-0@1.0",
            "parents_total": 2,
        }
        assert rec.action["deepest_chains_total"] == 3


class TestAnalyzeDuplicatePackagesEmpty:
    def test_empty_returns_empty(self):
        assert analyze_duplicate_packages([]) == []


class TestAnalyzeDuplicatePackagesFound:
    """Two packages from the same SIMILAR_PACKAGE_GROUPS category trigger a duplicate."""

    def test_http_clients_duplicate(self):
        deps = [
            _dep("axios", version="1.0", direct=True),
            _dep("got", version="12.0", direct=True),
        ]
        result = analyze_duplicate_packages(deps)
        assert len(result) == 1

    def test_http_clients_type(self):
        deps = [
            _dep("axios", version="1.0", direct=True),
            _dep("got", version="12.0", direct=True),
        ]
        rec = analyze_duplicate_packages(deps)[0]
        assert rec.type == RecommendationType.DUPLICATE_FUNCTIONALITY

    def test_http_clients_priority_low(self):
        deps = [
            _dep("axios", version="1.0", direct=True),
            _dep("got", version="12.0", direct=True),
        ]
        rec = analyze_duplicate_packages(deps)[0]
        assert rec.priority == Priority.LOW

    def test_http_clients_affected_components(self):
        deps = [
            _dep("axios", version="1.0", direct=True),
            _dep("got", version="12.0", direct=True),
        ]
        rec = analyze_duplicate_packages(deps)[0]
        assert any("HTTP Clients" in c for c in rec.affected_components)

    def test_date_libraries_duplicate(self):
        deps = [
            _dep("moment", version="2.29.0", direct=True),
            _dep("dayjs", version="1.11.0", direct=True),
        ]
        result = analyze_duplicate_packages(deps)
        assert len(result) == 1

    def test_utility_libraries_duplicate(self):
        deps = [
            _dep("lodash", version="4.17.21", direct=True),
            _dep("underscore", version="1.13.0", direct=True),
        ]
        result = analyze_duplicate_packages(deps)
        assert len(result) == 1


class TestAnalyzeDuplicatePackagesSingleFromCategory:
    def test_single_http_client_no_duplicate(self):
        deps = [_dep("axios", version="1.0", direct=True)]
        result = analyze_duplicate_packages(deps)
        assert len(result) == 0


class TestAnalyzeDuplicatePackagesMultipleCategories:
    def test_multiple_categories_single_recommendation(self):
        deps = [
            _dep("axios", version="1.0", direct=True),
            _dep("got", version="12.0", direct=True),
            _dep("moment", version="2.29.0", direct=True),
            _dep("dayjs", version="1.11.0", direct=True),
        ]
        result = analyze_duplicate_packages(deps)
        assert len(result) == 1
        assert result[0].impact["total"] == 2

    def test_multiple_categories_all_listed(self):
        deps = [
            _dep("axios", version="1.0", direct=True),
            _dep("got", version="12.0", direct=True),
            _dep("moment", version="2.29.0", direct=True),
            _dep("dayjs", version="1.11.0", direct=True),
        ]
        rec = analyze_duplicate_packages(deps)[0]
        components = " ".join(rec.affected_components)
        assert "HTTP Clients" in components
        assert "Date/Time Libraries" in components
