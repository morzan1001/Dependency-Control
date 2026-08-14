"""Analytics joins dependency names against finding components.

Prod stores the dependency name bare with the Maven group in a separate field
(``jackson-databind`` + ``group: com.fasterxml.jackson.core``) while the aggregated
vulnerability finding carries the qualified coordinate, so the join has to resolve a
bare dependency name onto a qualified finding component.
"""

import asyncio

from app.api.v1.endpoints.analytics.dependencies import _build_dependency_graph, _component_name_query
from app.api.v1.helpers.analytics import build_findings_severity_map
from tests.mocks.fake_mongo import FakeDatabase


def _finding(component, severity="HIGH"):
    return {"component": component, "severity": severity}


def _dep(name, version="2.20.2", purl=None):
    return {
        "purl": purl or f"pkg:maven/com.fasterxml.jackson.core/{name}@{version}?type=jar",
        "name": name,
        "version": version,
        "type": "library",
        "direct": True,
        "parent_components": [],
    }


class TestBareDependencyNameResolvesQualifiedFinding:
    def test_maven_artifact_id_finds_group_qualified_component(self):
        findings_map = build_findings_severity_map(
            [_finding("com.fasterxml.jackson.core:jackson-databind", "CRITICAL")]
        )

        graph = _build_dependency_graph([_dep("jackson-databind")], findings_map)

        node = graph.nodes[0]
        assert node.findings_count == 1
        assert node.findings_severity is not None
        assert node.findings_severity.critical == 1

    def test_exact_component_still_wins_over_the_artifact_alias(self):
        findings_map = build_findings_severity_map(
            [
                _finding("@angular-devkit/core", "HIGH"),
                _finding("@angular/core", "CRITICAL"),
                _finding("@angular/core", "CRITICAL"),
            ]
        )

        graph = _build_dependency_graph(
            [_dep("@angular-devkit/core", "19.2.15", purl="pkg:npm/%40angular-devkit/core@19.2.15")],
            findings_map,
        )

        node = graph.nodes[0]
        assert node.findings_count == 1
        assert node.findings_severity is not None
        assert node.findings_severity.high == 1

    def test_ambiguous_bare_name_gets_no_overlay(self):
        """Three packages end in 'core'; a bare 'core' dependency must not inherit one of them."""
        findings_map = build_findings_severity_map([_finding("@angular/core"), _finding("@messageformat/core")])

        graph = _build_dependency_graph([_dep("core", "21.1.5", purl="pkg:npm/%40angular/core@21.1.5")], findings_map)

        node = graph.nodes[0]
        assert node.findings_count == 0
        assert node.has_findings is False


class TestComponentFindingsLookup:
    def _components(self, query):
        db = FakeDatabase()
        for idx, component in enumerate(
            ["com.fasterxml.jackson.core:jackson-databind", "jackson-databind", "spring-jackson-databind"]
        ):
            asyncio.run(
                db.findings.insert_one(
                    {"_id": f"f{idx}", "scan_id": "scan-1", "type": "vulnerability", "component": component}
                )
            )
        docs = asyncio.run(db.findings.find({"scan_id": "scan-1", **query}).to_list(None))
        return sorted(d["component"] for d in docs)

    def test_bare_name_reaches_the_qualified_component(self):
        assert self._components(_component_name_query("jackson-databind")) == [
            "com.fasterxml.jackson.core:jackson-databind",
            "jackson-databind",
        ]

    def test_qualified_name_matches_itself(self):
        assert self._components(_component_name_query("com.fasterxml.jackson.core:jackson-databind")) == [
            "com.fasterxml.jackson.core:jackson-databind"
        ]
