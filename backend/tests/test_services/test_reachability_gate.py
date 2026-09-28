"""The falsification gate: a callgraph may only mark a finding unreachable when the
producer listed that package in ``analyzed_modules`` for a language covering its ecosystem."""

import pytest

from app.core.constants import REACHABILITY_REASON_ABSENCE_NOT_EVIDENCE, REACHABILITY_REASON_LANGUAGE_NOT_ANALYZED
from app.services.component_identity import canonical_module_key
from app.schemas.projections import CallgraphMinimal
from app.services.reachability_enrichment import (
    _enrich_finding_from_callgraphs,
    _lists_package,
    _prepare_callgraph,
    component_language_map,
    reachability_display_tier,
)

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


def _enrich(finding, prepared, component_languages=None):
    assert _enrich_finding_from_callgraphs(finding, [prepared], component_languages) is True
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
        reach = _enrich(finding, prepared)
        assert reach["is_reachable"] is True
        assert reach["import_locations"] == ["app/client.py"]

    def test_coordinate_component_resolves_against_a_bare_keyed_usage(self):
        finding = _finding(component=self._COORDINATE)
        prepared = _prepared(
            language="java", module_usage=_usage("jackson-databind"), analyzed_modules=["jackson-databind"]
        )
        reach = _enrich(finding, prepared)
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
        assert reach["unknown_reason"] == REACHABILITY_REASON_LANGUAGE_NOT_ANALYZED

    def test_the_python_twin_is_still_falsified(self):
        assert self._verdict("3.0.2")["is_reachable"] is False

    def test_a_version_neither_lists_needs_every_ecosystem_covered(self):
        assert self._verdict("9.9.9")["is_reachable"] is None


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
        assert reach["unknown_reason"] == REACHABILITY_REASON_ABSENCE_NOT_EVIDENCE

    def test_without_a_java_graph_the_verdict_asks_for_one(self):
        reach = self._verdict(_prepared(language="python", analyzed_modules=["requests"]))

        assert reach["unknown_reason"] == REACHABILITY_REASON_LANGUAGE_NOT_ANALYZED
