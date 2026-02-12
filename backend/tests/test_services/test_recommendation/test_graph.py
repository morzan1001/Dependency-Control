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
    """Empty input."""

    def test_empty_returns_empty(self):
        assert analyze_deep_dependency_chains([]) == []


class TestAnalyzeDeepDependencyChainsShallow:
    """Direct deps have depth 1, no deep chain warning."""

    def test_direct_deps_no_warning(self):
        deps = [
            _dep("express", version="4.18.0", direct=True),
            _dep("lodash", version="4.17.21", direct=True),
        ]
        result = analyze_deep_dependency_chains(deps, max_dependency_depth=3)
        assert len(result) == 0

    def test_shallow_transitive_no_warning(self):
        # direct -> child (depth 2), well within default max_dependency_depth=8
        parent = _dep("express", version="4.18.0", direct=True)
        child = _dep("body-parser", version="1.20.0", direct=False,
                      parent_components=["pkg:npm/express@4.18.0"])
        result = analyze_deep_dependency_chains([parent, child], max_dependency_depth=8)
        assert len(result) == 0


class TestAnalyzeDeepDependencyChainsDeep:
    """Deps nested deeper than max_dependency_depth."""

    def _build_chain(self, length):
        """Build a linear dependency chain of given length."""
        deps = []
        # Root at depth 1
        deps.append(_dep("pkg-0", version="1.0", direct=True))

        for i in range(1, length):
            deps.append(_dep(
                f"pkg-{i}",
                version="1.0",
                direct=False,
                parent_components=[f"pkg:npm/pkg-{i - 1}@1.0"],
            ))
        return deps

    def test_chain_exceeding_max_depth_produces_recommendation(self):
        # Chain of 5 deep, max_dependency_depth=3
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
        # Chain of 3, max_dependency_depth=3 => max depth is 3, not > 3
        deps = self._build_chain(3)
        result = analyze_deep_dependency_chains(deps, max_dependency_depth=3)
        deep_recs = [r for r in result if "max depth" in r.title]
        assert len(deep_recs) == 0


class TestAnalyzeDeepDependencyChainsCircular:
    """Circular dependencies detection."""

    def test_circular_detected(self):
        deps_circular = [
            {
                "name": "pkg-a", "version": "1.0",
                "purl": "pkg:npm/pkg-a@1.0",
                "direct": True,
                "parent_components": ["pkg:npm/pkg-b@1.0"],
            },
            {
                "name": "pkg-b", "version": "1.0",
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
                "name": "pkg-a", "version": "1.0",
                "purl": "pkg:npm/pkg-a@1.0",
                "direct": True,
                "parent_components": ["pkg:npm/pkg-b@1.0"],
            },
            {
                "name": "pkg-b", "version": "1.0",
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
                "name": "pkg-a", "version": "1.0",
                "purl": "pkg:npm/pkg-a@1.0",
                "direct": True,
                "parent_components": ["pkg:npm/pkg-b@1.0"],
            },
            {
                "name": "pkg-b", "version": "1.0",
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


class TestAnalyzeDeepDependencyChainsBothCircularAndDeep:
    """Both circular and deep chain issues produce two recommendations."""

    def test_both_circular_and_deep(self):
        # Circular pair
        circular_deps = [
            {
                "name": "circ-a", "version": "1.0",
                "purl": "pkg:npm/circ-a@1.0",
                "direct": True,
                "parent_components": ["pkg:npm/circ-b@1.0"],
            },
            {
                "name": "circ-b", "version": "1.0",
                "purl": "pkg:npm/circ-b@1.0",
                "direct": False,
                "parent_components": ["pkg:npm/circ-a@1.0"],
            },
        ]

        # Deep chain: root -> d1 -> d2 -> d3 -> d4 (depth 5, max=2)
        deep_chain = [
            _dep("root", version="1.0", direct=True),
        ]
        for i in range(1, 5):
            deep_chain.append(_dep(
                f"deep-{i}", version="1.0", direct=False,
                parent_components=[f"pkg:npm/{'root' if i == 1 else f'deep-{i-1}'}@1.0"],
            ))

        all_deps = circular_deps + deep_chain
        result = analyze_deep_dependency_chains(all_deps, max_dependency_depth=2)
        assert len(result) == 2
        titles = [r.title for r in result]
        assert any("Circular" in t for t in titles)
        assert any("max depth" in t.lower() or "deep" in t.lower() for t in titles)


class TestAnalyzeDuplicatePackagesEmpty:
    """Empty input."""

    def test_empty_returns_empty(self):
        assert analyze_duplicate_packages([]) == []


class TestAnalyzeDuplicatePackagesFound:
    """Two packages from the same SIMILAR_PACKAGE_GROUPS category."""

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
    """Only one package from a category does not trigger duplicate."""

    def test_single_http_client_no_duplicate(self):
        deps = [_dep("axios", version="1.0", direct=True)]
        result = analyze_duplicate_packages(deps)
        assert len(result) == 0


class TestAnalyzeDuplicatePackagesMultipleCategories:
    """Multiple categories with duplicates produce single recommendation."""

    def test_multiple_categories_single_recommendation(self):
        deps = [
            # HTTP clients
            _dep("axios", version="1.0", direct=True),
            _dep("got", version="12.0", direct=True),
            # Date libraries
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
