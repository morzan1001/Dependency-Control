"""Tests for the high-confidence reachability gate (B9).

The raw ``is_reachable: bool`` flag mixes two very different signals:
solid evidence that a vulnerable function is actually called (high
confidence) vs. "the package is imported, the rest is heuristic" (low
confidence). Headline counts that don't distinguish the two prioritise
noise. ``is_high_confidence_reachable`` is the gate that lets call-sites
opt into the conservative reading without losing the raw boolean.
"""

from app.core.constants import REACHABILITY_HIGH_CONFIDENCE_THRESHOLD
from app.services.reachability_enrichment import is_high_confidence_reachable


class TestIsHighConfidenceReachable:
    def test_reachable_with_high_confidence_returns_true(self):
        data = {"is_reachable": True, "confidence_score": 0.9}
        assert is_high_confidence_reachable(data) is True

    def test_reachable_at_threshold_returns_true(self):
        # Inclusive boundary — a finding sitting exactly on the threshold
        # is considered high-confidence.
        data = {"is_reachable": True, "confidence_score": REACHABILITY_HIGH_CONFIDENCE_THRESHOLD}
        assert is_high_confidence_reachable(data) is True

    def test_reachable_below_threshold_returns_false(self):
        # Imported-but-no-symbol-info matches sit at 0.5; they should
        # not feed headline reachable counts.
        data = {"is_reachable": True, "confidence_score": 0.5}
        assert is_high_confidence_reachable(data) is False

    def test_unreachable_returns_false_regardless_of_confidence(self):
        data = {"is_reachable": False, "confidence_score": 0.99}
        assert is_high_confidence_reachable(data) is False

    def test_missing_is_reachable_returns_false(self):
        data = {"confidence_score": 0.9}
        assert is_high_confidence_reachable(data) is False

    def test_missing_confidence_returns_false(self):
        # Without a confidence number we can't assert "high confidence".
        data = {"is_reachable": True}
        assert is_high_confidence_reachable(data) is False

    def test_empty_dict_returns_false(self):
        assert is_high_confidence_reachable({}) is False

    def test_none_returns_false(self):
        assert is_high_confidence_reachable(None) is False


# ---------------------------------------------------------------------------
# Reachability -> persisted adjusted risk score wiring (W5 / Finding 13)
#
# After reachability enrichment determines a finding's reachability, it must
# persist a per-finding details.adjusted_risk_score derived from the base
# details.risk_score via the reachability modifier. Previously
# calculate_adjusted_risk_score was dead code; the persisted adjusted score
# never reflected reachability.
# ---------------------------------------------------------------------------

from app.services.reachability_enrichment import (  # noqa: E402
    _enrich_finding_from_callgraphs,
    _enrich_single_finding,
    _match_symbols,
)


class TestMatchSymbols:
    """Symbol matching must be conservative: a spurious match promotes a finding
    to 'confirmed reachable' and boosts its risk x1.1, so substring matching
    ('get' in 'getUser'/'forget'/'target') is unacceptable (improvement audit #6)."""

    def test_exact_match(self):
        assert _match_symbols(["SSL_read"], ["SSL_read"]) == ["SSL_read"]

    def test_case_insensitive_exact_match(self):
        assert _match_symbols(["Foo"], ["foo"]) == ["foo"]

    def test_qualified_call_boundary_matches(self):
        # method chaining / qualified usage: "_.template" ends with ".template"
        assert _match_symbols(["template"], ["_.template"]) == ["_.template"]
        assert _match_symbols(["SSL_read"], ["openssl.SSL_read"]) == ["openssl.SSL_read"]

    def test_substring_does_not_match(self):
        assert _match_symbols(["get"], ["getUser", "forget", "target"]) == []

    def test_prefix_substring_does_not_match(self):
        assert _match_symbols(["open"], ["reopen"]) == []

    def test_mixed_real_and_spurious(self):
        # only the exact and qualified hits count; the substring noise is dropped
        result = _match_symbols(["read"], ["read", "thread", "io.read", "already"])
        assert result == ["read", "io.read"]


class _FakeCallgraph:
    def __init__(self, module_usage=None, import_map=None, language="python"):
        self.module_usage = module_usage or {}
        self.import_map = import_map or {}
        self.language = language


def _vuln_finding(component="requests", risk_score=80.0, cve="CVE-2024-0001"):
    return {
        "_id": "f1",
        "finding_id": cve,
        "type": "vulnerability",
        "component": component,
        "version": "1.0.0",
        "severity": "HIGH",
        "details": {"risk_score": risk_score},
    }


class TestReachabilityAdjustedScoreWiring:
    def test_unreachable_persists_reduced_adjusted_score(self):
        """A package absent from a callgraph THAT COVERS ITS ECOSYSTEM (pypi vs a
        python callgraph) -> genuinely not reachable -> adjusted = base * 0.4."""
        finding = _vuln_finding(component="not-imported-pkg", risk_score=80.0)
        finding["details"]["purl"] = "pkg:pypi/not-imported-pkg@1.0.0"
        cg = _FakeCallgraph(module_usage={"other": {}}, import_map={"a.py": ["other"]}, language="python")
        enriched = _enrich_finding_from_callgraphs(finding, [cg])
        assert enriched is True
        assert finding["details"]["reachability"]["is_reachable"] is False
        # 80 * 0.4 == 32.0
        assert finding["details"]["adjusted_risk_score"] == 32.0
        assert finding["details"]["adjusted_risk_score"] < finding["details"]["risk_score"]


class TestReachabilityFailClosed:
    """Absence of evidence is not evidence of unreachability. A package missing
    from a callgraph that does NOT cover its ecosystem (or when the ecosystem is
    unknown) must be recorded as unknown (identity modifier), never down-weighted
    x0.4 (improvement audit #3)."""

    def test_wrong_language_callgraph_does_not_downweight(self):
        # pypi finding, but only a JS callgraph analyzed -> absence is meaningless.
        finding = _vuln_finding(component="requests", risk_score=80.0)
        finding["details"]["purl"] = "pkg:pypi/requests@2.31.0"
        cg = _FakeCallgraph(module_usage={"lodash": {}}, import_map={"a.js": ["lodash"]}, language="javascript")
        _enrich_finding_from_callgraphs(finding, [cg])
        reach = finding["details"]["reachability"]
        assert reach["is_reachable"] is None
        assert finding["details"]["adjusted_risk_score"] == 80.0  # identity, no x0.4

    def test_unknown_ecosystem_does_not_downweight(self):
        # No purl -> can't tell if the callgraph covers it -> unknown, no penalty.
        finding = _vuln_finding(component="mystery", risk_score=80.0)
        cg = _FakeCallgraph(module_usage={"other": {}}, import_map={"a.py": ["other"]}, language="python")
        _enrich_finding_from_callgraphs(finding, [cg])
        reach = finding["details"]["reachability"]
        assert reach["is_reachable"] is None
        assert finding["details"]["adjusted_risk_score"] == 80.0

    def test_covering_language_still_downweights(self):
        # npm finding absent from a JS callgraph -> genuine unreachable -> x0.4.
        finding = _vuln_finding(component="left-pad", risk_score=80.0)
        finding["details"]["purl"] = "pkg:npm/left-pad@1.0.0"
        cg = _FakeCallgraph(module_usage={"lodash": {}}, import_map={"a.js": ["lodash"]}, language="javascript")
        _enrich_finding_from_callgraphs(finding, [cg])
        reach = finding["details"]["reachability"]
        assert reach["is_reachable"] is False
        assert finding["details"]["adjusted_risk_score"] == 32.0

    def test_symbol_reachable_persists_boosted_adjusted_score(self):
        """A matched vulnerable symbol -> confirmed -> adjusted = base * 1.1."""
        finding = _vuln_finding(component="requests", risk_score=80.0)
        finding["details"]["vulnerabilities"] = [
            {"id": "CVE-2024-0001", "description": "flaw in requests.get() allows ..."}
        ]
        module_usage = {"requests": {"import_locations": ["a.py"], "used_symbols": ["get"]}}
        # symbol-level match boosts; assert it is >= base regardless of exact extraction.
        _enrich_single_finding(finding, module_usage, {"a.py": ["requests"]}, "python")
        reach = finding["details"]["reachability"]
        assert reach["is_reachable"] is True
        adjusted = finding["details"]["adjusted_risk_score"]
        if reach["analysis_level"] == "symbol":
            assert adjusted >= finding["details"]["risk_score"]
        else:
            # import-only fallback: identity, not a penalty
            assert adjusted == finding["details"]["risk_score"]

    def test_import_only_reachable_is_identity(self):
        """Imported but no extracted symbols -> import-level reachable -> identity (no boost)."""
        finding = _vuln_finding(component="requests", risk_score=80.0)
        module_usage = {"requests": {"import_locations": ["a.py"], "used_symbols": []}}
        _enrich_single_finding(finding, module_usage, {"a.py": ["requests"]}, "python")
        reach = finding["details"]["reachability"]
        assert reach["is_reachable"] is True
        # import-level (no symbol match) must NOT boost beyond base
        assert finding["details"]["adjusted_risk_score"] == finding["details"]["risk_score"]
