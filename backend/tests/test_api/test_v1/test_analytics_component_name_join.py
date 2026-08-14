"""Analytics joins dependency names against finding components.

Prod stores the dependency name bare with the Maven group in a separate field
(``jackson-databind`` + ``group: com.fasterxml.jackson.core``) while the aggregated
vulnerability finding carries the qualified coordinate, so the join has to resolve a
bare dependency name onto a qualified finding component.
"""

import asyncio

from app.api.v1.endpoints.analytics.dependencies import _build_dependency_graph
from app.api.v1.helpers.analytics import build_findings_severity_map
from app.services.aggregation.components import component_match_query
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
        assert self._components(component_match_query("jackson-databind")) == [
            "com.fasterxml.jackson.core:jackson-databind",
            "jackson-databind",
        ]

    def test_qualified_name_matches_itself(self):
        assert self._components(component_match_query("com.fasterxml.jackson.core:jackson-databind")) == [
            "com.fasterxml.jackson.core:jackson-databind"
        ]


class TestAliasLookupIsCaseInsensitive:
    """The bare-artifact alias is lowercased; dependency names preserve their case.

    Prod has 3 demoted documents for `xercesImpl` today, and `HikariCP`-style artifact
    names generalise the problem.
    """

    def test_mixed_case_maven_artifact_resolves_its_qualified_finding(self):
        findings_map = build_findings_severity_map([_finding("xerces:xercesImpl", "HIGH")])

        graph = _build_dependency_graph(
            [_dep("xercesImpl", "2.12.2", purl="pkg:maven/xerces/xercesImpl@2.12.2")], findings_map
        )

        assert graph.nodes[0].findings_count == 1

    def test_vuln_count_map_resolves_a_mixed_case_dependency_name(self):
        from app.services.aggregation.components import build_component_index, lookup_component

        counts = build_component_index({"com.zaxxer:HikariCP": 4})

        assert lookup_component(counts, "HikariCP") == 4
