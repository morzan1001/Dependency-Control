"""The falsification gate: a callgraph may only mark a finding unreachable when the
producer listed that package in ``analyzed_modules`` for a language covering its ecosystem."""

import json
from pathlib import Path

import pytest

from app.api.v1.helpers.callgraph import ParsedCallgraph, parse_generic_format, parse_madge_format
from app.core.risk_scoring import reachability_display_tier
from app.schemas.finding_details import ReachabilityInfo
from app.services.component_identity import canonical_module_key
from app.schemas.projections import CallgraphMinimal
from app.services.reachability_enrichment import (
    _enrich_finding_from_callgraphs,
    _lists_package,
    _prepare_callgraph,
    component_language_map,
    enrich_findings_with_reachability,
)
from app.services.sbom_parser import parse_sbom

_BASE_RISK = 80.0


def _prepared(language="python", module_usage=None, analyzed_modules=None):
    """A prepared callgraph built through the same projection production reads."""
    return _prepare_callgraph(
        CallgraphMinimal(
            _id="cg-1",
            language=language,
            module_usage=module_usage or {},
            analyzed_modules=analyzed_modules or [],
        )
    )


def _usage(module, locations=("app/client.py",), symbols=()):
    return {module: {"module": module, "import_locations": list(locations), "used_symbols": list(symbols)}}


def _finding(component="requests", symbols=None, in_kev=False):
    details = {"risk_score": _BASE_RISK}
    if symbols is not None:
        details["vulnerabilities"] = [{"id": "CVE-2024-0001", "ecosystem_specific": {"symbols": list(symbols)}}]
    if in_kev:
        details["in_kev"] = True
    return {
        "_id": "f1",
        "finding_id": "CVE-2024-0001",
        "type": "vulnerability",
        "component": component,
        "version": "1.0.0",
        "severity": "HIGH",
        "details": details,
    }


def _enrich(finding, prepared, component_languages):
    _enrich_finding_from_callgraphs(finding, [prepared], component_languages)
    return finding["details"]["reachability"]


_PY = component_language_map([{"name": "requests", "version": "1.0.0", "type": "pypi"}])


class TestFalsificationMatrix:
    """analyzed_modules x language coverage x usage -> the tri-state verdict."""

    def test_in_coverage_universe_and_unused_is_unreachable(self):
        finding = _finding()
        prepared = _prepared(module_usage=_usage("urllib3"), analyzed_modules=["requests", "urllib3"])
        reach = _enrich(finding, prepared, _PY)
        assert reach["is_reachable"] is False
        assert finding["details"]["adjusted_risk_score"] == 32.0

    def test_empty_coverage_universe_yields_unknown(self):
        finding = _finding()
        prepared = _prepared(module_usage=_usage("urllib3"), analyzed_modules=[])
        reach = _enrich(finding, prepared, _PY)
        assert reach["is_reachable"] is None
        assert finding["details"]["adjusted_risk_score"] == _BASE_RISK

    def test_language_outside_the_ecosystem_yields_unknown(self):
        finding = _finding()
        prepared = _prepared(
            language="javascript", module_usage=_usage("lodash"), analyzed_modules=["requests", "lodash"]
        )
        reach = _enrich(finding, prepared, _PY)
        assert reach["is_reachable"] is None
        assert finding["details"]["adjusted_risk_score"] == _BASE_RISK

    def test_package_used_is_reachable(self):
        finding = _finding()
        prepared = _prepared(module_usage=_usage("requests"), analyzed_modules=["requests"])
        reach = _enrich(finding, prepared, _PY)
        assert reach["is_reachable"] is True
        assert reach["import_locations"] == ["app/client.py"]
        assert finding["details"]["adjusted_risk_score"] == _BASE_RISK

    def test_absent_from_a_non_empty_coverage_universe_yields_unknown(self):
        finding = _finding()
        prepared = _prepared(module_usage=_usage("urllib3"), analyzed_modules=["urllib3"])
        reach = _enrich(finding, prepared, _PY)
        assert reach["is_reachable"] is None
        assert finding["details"]["adjusted_risk_score"] == _BASE_RISK


class TestKevCarveOut:
    def test_kev_at_import_level_keeps_its_full_score(self):
        finding = _finding(in_kev=True)
        prepared = _prepared(module_usage=_usage("urllib3"), analyzed_modules=["requests", "urllib3"])
        reach = _enrich(finding, prepared, _PY)
        assert reach["is_reachable"] is False
        assert reach["analysis_level"] == "import"
        assert finding["details"]["adjusted_risk_score"] == _BASE_RISK

    def test_kev_at_symbol_level_still_gets_the_confirmed_boost(self):
        finding = _finding(symbols=["get"], in_kev=True)
        prepared = _prepared(
            module_usage=_usage("requests", symbols=["get"]),
            analyzed_modules=["requests"],
        )
        reach = _enrich(finding, prepared, _PY)
        assert reach["is_reachable"] is True
        assert reach["analysis_level"] == "symbol"
        assert reach["matched_symbols"] == ["get"]
        assert finding["details"]["adjusted_risk_score"] == 88.0


class TestNegativeSymbolMatch:
    def test_searched_and_unmatched_symbols_stay_likely(self):
        finding = _finding(symbols=["get"])
        prepared = _prepared(
            module_usage=_usage("requests", symbols=["post"]),
            analyzed_modules=["requests"],
        )
        reach = _enrich(finding, prepared, _PY)
        assert reach["matched_symbols"] == []
        assert reach["analysis_level"] == "import"
        assert reachability_display_tier(reach["is_reachable"], reach["analysis_level"]) == "likely"
        assert finding["details"]["adjusted_risk_score"] == _BASE_RISK


class TestAliasResolution:
    """A Maven coordinate and its bare artifact name are the same package on both sides."""

    _COORDINATE = "com.fasterxml.jackson.core:jackson-databind"

    def test_bare_component_resolves_against_a_coordinate_keyed_usage(self):
        finding = _finding(component="jackson-databind")
        prepared = _prepared(
            language="java", module_usage=_usage(self._COORDINATE), analyzed_modules=[self._COORDINATE]
        )
        reach = _enrich(finding, prepared, {})
        assert reach["is_reachable"] is True
        assert reach["import_locations"] == ["app/client.py"]

    def test_coordinate_component_resolves_against_a_bare_keyed_usage(self):
        finding = _finding(component=self._COORDINATE)
        prepared = _prepared(
            language="java", module_usage=_usage("jackson-databind"), analyzed_modules=["jackson-databind"]
        )
        reach = _enrich(finding, prepared, {})
        assert reach["is_reachable"] is True
        assert reach["import_locations"] == ["app/client.py"]

    @pytest.mark.parametrize(
        ("component", "analyzed"),
        [("jackson-databind", _COORDINATE), (_COORDINATE, "jackson-databind")],
    )
    def test_coverage_universe_resolves_either_spelling(self, component, analyzed):
        prepared = _prepared(language="java", analyzed_modules=[analyzed])
        assert _lists_package(prepared, component) is True


class TestWriteSideMeetsReadSide:
    """Keys stored by ``canonical_module_key`` must resolve from the finding's own spelling."""

    @pytest.mark.parametrize("component", ["PyYAML", "typing-extensions"])
    def test_python_canonical_key_is_found_by_the_finding_component(self, component):
        stored_key = canonical_module_key(component, "python")
        assert stored_key != component

        finding = _finding(component=component)
        prepared = _prepared(module_usage=_usage(stored_key), analyzed_modules=[stored_key])
        reach = _enrich(finding, prepared, component_language_map([{"name": component, "type": "pypi"}]))
        assert reach["is_reachable"] is True
        assert reach["import_locations"] == ["app/client.py"]


class TestSameNameInTwoEcosystems:
    """A name two ecosystems share resolves per finding; one ecosystem's graph cannot speak for the other."""

    _DEPS = (
        {"name": "semver", "version": "5.7.1", "type": "npm", "purl": "pkg:npm/semver@5.7.1"},
        {"name": "semver", "version": "3.0.2", "type": "pypi", "purl": "pkg:pypi/semver@3.0.2"},
    )

    def _verdict(self, version):
        finding = {**_finding(component="semver"), "version": version}
        prepared = _prepared(module_usage=_usage("requests"), analyzed_modules=["semver", "requests"])
        return _enrich(finding, prepared, component_language_map(self._DEPS))

    def test_a_python_graph_cannot_falsify_the_npm_twin(self):
        reach = self._verdict("5.7.1")

        assert reach["is_reachable"] is None
        assert "No javascript/typescript callgraph was uploaded" in reach["message"]

    def test_the_python_twin_is_still_falsified(self):
        assert self._verdict("3.0.2")["is_reachable"] is False

    def test_a_version_neither_lists_needs_every_ecosystem_covered(self):
        assert self._verdict("9.9.9")["is_reachable"] is None


class TestPositiveEvidenceStaysInItsEcosystem:
    """An import in one ecosystem's graph is no evidence for a package of the same name in another."""

    _JS_IMPORTS_REDIS = _prepared(
        language="javascript", module_usage=_usage("redis", locations=("web/cache.js",)), analyzed_modules=["redis"]
    )

    def _verdict(self, version, deps, graphs):
        finding = {**_finding(component="redis"), "version": version}
        _enrich_finding_from_callgraphs(finding, graphs, component_language_map(deps))
        return finding["details"]["reachability"]

    def test_an_npm_import_leaves_the_pypi_twin_to_the_python_graph(self):
        python_lists_redis = _prepared(module_usage=_usage("requests"), analyzed_modules=["redis", "requests"])
        deps = [{"name": "redis", "version": "4.5.1", "type": "pypi", "purl": "pkg:pypi/redis@4.5.1"}]

        reach = self._verdict("4.5.1", deps, [self._JS_IMPORTS_REDIS, python_lists_redis])

        assert (reach["is_reachable"], reach["import_locations"]) == (False, [])
        assert reach["message"].endswith("(python).")

    def test_an_npm_import_says_nothing_about_an_alpine_package(self):
        deps = [{"name": "redis", "version": "7.2.4-r0", "type": "apk", "purl": "pkg:apk/alpine/redis@7.2.4-r0"}]

        reach = self._verdict("7.2.4-r0", deps, [self._JS_IMPORTS_REDIS])

        assert reach["is_reachable"] is None
        assert "ecosystem no callgraph tool supports" in reach["message"]

    def test_a_package_the_inventory_does_not_know_takes_evidence_from_any_graph(self):
        assert self._verdict("4.5.1", [], [self._JS_IMPORTS_REDIS])["is_reachable"] is True

    def test_a_version_no_row_lists_names_only_the_callgraph_languages_it_lacks(self):
        deps = [
            {"name": "redis", "version": "7.2.4-r0", "type": "apk", "purl": "pkg:apk/alpine/redis@7.2.4-r0"},
            {"name": "redis", "version": "4.6.0", "type": "npm", "purl": "pkg:npm/redis@4.6.0"},
        ]

        reach = self._verdict("9.9.9", deps, [_prepared(analyzed_modules=["requests"])])

        assert reach["message"].startswith("No javascript/typescript callgraph was uploaded")


class TestJvmCoverage:
    """A Java callgraph covers Maven packages, but its missing imports are no evidence of absence."""

    _COORDINATE = "com.fasterxml.jackson.core:jackson-databind"
    _DEPS = (
        {
            "name": "jackson-databind",
            "version": "2.15.0",
            "type": "maven",
            "purl": "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.15.0",
        },
    )

    def _verdict(self, prepared):
        finding = {**_finding(component=self._COORDINATE), "version": "2.15.0"}
        return _enrich(finding, prepared, component_language_map(self._DEPS))

    def test_a_listed_but_unimported_package_stays_unknown_for_that_reason(self):
        prepared = _prepared(
            language="java", module_usage=_usage("com.google.guava:guava"), analyzed_modules=[self._COORDINATE]
        )

        reach = self._verdict(prepared)

        assert reach["is_reachable"] is None
        assert "cannot see reflective loading" in reach["message"]

    def test_without_a_java_graph_the_verdict_asks_for_one(self):
        reach = self._verdict(_prepared(language="python", analyzed_modules=["requests"]))

        assert "No groovy/java/kotlin/scala callgraph was uploaded" in reach["message"]


_SBOM_FIXTURES = Path(__file__).parent.parent / "fixtures" / "sbom"


def _inventory(*fixtures):
    """The language map of the dependencies the real SBOM parser extracts from these fixtures."""
    return component_language_map(
        dep.model_dump()
        for name in fixtures
        for dep in parse_sbom(json.loads((_SBOM_FIXTURES / name).read_text())).dependencies
    )


def _stored(parsed: ParsedCallgraph, language):
    """The projection production reads back for an upload the real parser produced."""
    return CallgraphMinimal(
        _id=f"cg-{language}",
        language=language,
        module_usage={key: usage.model_dump() for key, usage in parsed.module_usage.items()},
        analyzed_modules=parsed.analyzed_modules,
    )


class TestDependencyDepth:
    """First-party code need not import a transitive package, so its absence falsifies nothing."""

    # First-party code imports anyio only, while the producer lists the whole installed set.
    _GRAPH = parse_generic_format(
        {
            "imports": [{"module": "anyio", "file": "app/worker.py", "line": 1, "symbols": ["run"]}],
            "analyzed_modules": ["anyio", "certifi", "httpx", "idna"],
        },
        "python",
    )

    def _verdict(self, component, version, *fixtures):
        finding = {**_finding(component=component), "version": version}
        enrich_findings_with_reachability([finding], [_stored(self._GRAPH, "python")], _inventory(*fixtures))
        return finding

    def test_a_confirmed_transitive_package_stays_unknown(self):
        finding = self._verdict("certifi", "2024.7.4", "mono.trivy.cdx.json")

        reach = finding["details"]["reachability"]
        assert reach["is_reachable"] is None
        assert "transitive" in reach["message"]
        assert finding["details"]["adjusted_risk_score"] == _BASE_RISK

    def test_a_direct_package_nothing_imports_is_falsified(self):
        finding = self._verdict("httpx", "0.27.0", "mono.trivy.cdx.json")

        assert finding["details"]["reachability"]["is_reachable"] is False
        assert finding["details"]["adjusted_risk_score"] == 32.0

    def test_an_inferred_depth_does_not_block_falsification(self):
        assert (
            self._verdict("certifi", "2024.7.4", "poetry.syft.json")["details"]["reachability"]["is_reachable"] is False
        )

    def test_one_confirmed_transitive_row_blocks_falsification(self):
        finding = self._verdict("certifi", "2024.7.4", "poetry.syft.json", "mono.trivy.cdx.json")

        assert finding["details"]["reachability"]["is_reachable"] is None


class TestEvidenceAcrossGraphs:
    """Every graph that lists a package contributes its evidence, whatever order the graphs load in."""

    _LODASH = component_language_map([{"name": "lodash", "version": "1.0.0", "type": "npm"}])

    @pytest.mark.parametrize("ts_first", [False, True], ids=["js_first", "ts_first"])
    def test_symbol_evidence_in_either_graph_confirms(self, ts_first):
        js = _stored(
            parse_madge_format(
                {"src/index.js": ["../node_modules/lodash/index.js"], "__analyzed_modules__": ["lodash"]},
                "javascript",
            ),
            "javascript",
        )
        ts = _stored(
            parse_generic_format(
                {"imports": [{"module": "lodash", "file": "src/app.ts", "line": 1, "symbols": ["template"]}]},
                "typescript",
            ),
            "typescript",
        )
        finding = _finding(component="lodash", symbols=["template"])

        enrich_findings_with_reachability([finding], [ts, js] if ts_first else [js, ts], self._LODASH)

        reach = finding["details"]["reachability"]
        assert reach["analysis_level"] == "symbol"
        assert reach["confidence_score"] == 1.0
        assert reach["matched_symbols"] == ["template"]
        assert reach["import_locations"] == ["src/app.ts", "src/index.js"]
        assert reach["import_location_count"] == 2
        assert finding["details"]["adjusted_risk_score"] == 88.0


class TestDefinitelyTypedImports:
    def test_an_import_resolved_to_its_types_stub_confirms_the_package(self):
        graph = _stored(
            parse_madge_format(
                {"src/index.ts": ["node_modules/@types/express/index.d.ts"], "__analyzed_modules__": ["express"]},
                "typescript",
            ),
            "typescript",
        )
        finding = _finding(component="express")
        deps = component_language_map([{"name": "express", "version": "1.0.0", "type": "npm", "direct": True}])

        enrich_findings_with_reachability([finding], [graph], deps)

        reach = finding["details"]["reachability"]
        assert (reach["is_reachable"], reach["import_locations"]) == (True, ["src/index.ts"])


class TestVerdictShape:
    def test_every_verdict_persists_only_declared_fields(self):
        graph = _stored(
            parse_generic_format(
                {
                    "imports": [{"module": "requests", "file": "app/client.py", "line": 1, "symbols": ["get"]}],
                    "analyzed_modules": ["requests", "urllib3"],
                },
                "python",
            ),
            "python",
        )
        languages = component_language_map(
            [
                {"name": "requests", "version": "1.0.0", "type": "pypi"},
                {"name": "urllib3", "version": "1.0.0", "type": "pypi"},
            ]
        )
        findings = [
            _finding(symbols=["get"]),
            _finding(symbols=["post"]),
            _finding(),
            _finding(component="urllib3"),
            _finding(component="libc6"),
        ]

        enrich_findings_with_reachability(findings, [graph], languages)

        verdicts = [finding["details"]["reachability"] for finding in findings]
        assert [verdict["is_reachable"] for verdict in verdicts] == [True, True, True, False, None]
        for verdict in verdicts:
            assert set(verdict) <= set(ReachabilityInfo.model_fields)
