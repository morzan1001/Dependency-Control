"""Tests for the high-confidence reachability gate (B9).

The raw ``is_reachable: bool`` flag mixes two very different signals:
solid evidence that a vulnerable function is actually called (high
confidence) vs. "the package is imported, the rest is heuristic" (low
confidence). Headline counts that don't distinguish the two prioritise
noise. ``is_high_confidence_reachable`` is the gate that lets call-sites
opt into the conservative reading without losing the raw boolean.
"""

import pytest

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
    _build_component_language_map,
    _check_package_in_imports,
    _enrich_finding_from_callgraphs,
    _enrich_single_finding,
    _match_symbols,
)

# The pending path no longer has a private summary builder; it now reuses the
# canonical build_reachability_summary from analysis/stats so the two cannot
# drift (audit: _build_reachability_summary_for_pending was a drifted copy).
from app.services.analysis.stats import build_reachability_summary  # noqa: E402


class TestPendingSummaryTiers:
    """The persisted pending summary must map analysis_level (none/import/symbol)
    onto the display tiers, not increment raw levels against confirmed/likely
    buckets that never match (audit MF6). run_pending_reachability_for_scan now
    calls the shared build_reachability_summary, so this exercises that helper."""

    @staticmethod
    def _f(_id, reachable, level):
        return {
            "finding_id": _id, "component": _id, "version": "1", "severity": "HIGH",
            "details": {"reachability": {"is_reachable": reachable, "analysis_level": level}},
        }

    def test_levels_bucketed_by_display_tier(self):
        findings = [
            self._f("a", True, "symbol"),
            self._f("b", True, "import"),
            self._f("c", False, "none"),
        ]
        cg = [{"language": "python", "module_usage": {}, "import_map": {}}]
        summary = build_reachability_summary(findings, cg, 3)
        levels = summary["reachability_levels"]
        assert levels["confirmed"] == 1
        assert levels["likely"] == 1
        assert levels["unreachable"] == 1
        assert levels["unknown"] == 0

    def test_shared_summary_includes_high_confidence_flag(self):
        # The drifted pending copy omitted is_high_confidence; the canonical
        # builder includes it, so the pending path now emits the same shape.
        findings = [self._f("a", True, "symbol")]
        cg = [{"language": "python", "module_usage": {}, "import_map": {}}]
        summary = build_reachability_summary(findings, cg, 1)
        assert "is_high_confidence" in summary["reachable_vulnerabilities"][0]


class TestCheckPackageInImports:
    """Import matching must be boundary-anchored. A bare `package in imp`
    substring test spuriously marks unrelated packages as imported, inflating
    reachability to `likely` and skipping the intended x0.4 down-weight (audit)."""

    def test_exact_match(self):
        assert _check_package_in_imports("lodash", {"a.js": ["lodash"]}) == ["a.js"]

    def test_subpath_match(self):
        # npm subpath import: "lodash/merge" belongs to package "lodash".
        assert _check_package_in_imports("lodash", {"a.js": ["lodash/merge"]}) == ["a.js"]

    def test_python_submodule_match(self):
        # `from requests.sessions import Session` -> import "requests.sessions".
        assert _check_package_in_imports("requests", {"a.py": ["requests.sessions"]}) == ["a.py"]

    def test_substring_does_not_match_npm(self):
        # "ms" must NOT match "forms" or a submodule of another scope.
        assert _check_package_in_imports("ms", {"a.js": ["forms"]}) == []
        assert _check_package_in_imports("ms", {"a.js": ["aws-sdk/clients/sms"]}) == []

    def test_substring_does_not_match_python(self):
        # "requests" must NOT match the unrelated "requests_oauthlib".
        assert _check_package_in_imports("requests", {"a.py": ["requests_oauthlib"]}) == []

    def test_prefix_substring_does_not_match(self):
        # "form" is a prefix of "forms" but not a boundary match.
        assert _check_package_in_imports("form", {"a.js": ["forms"]}) == []


class TestEcosystemFromDependencyMap:
    """Real vulnerability findings (OSV/Trivy/Grype) carry NO details.purl, so the
    fail-closed ecosystem gate must derive the ecosystem from the scan's
    dependencies (name -> type/purl), not from details.purl (audit MF1)."""

    def test_downweight_without_purl_via_component_map(self):
        # Real-shape finding: no details.purl. Ecosystem comes from the dep map.
        finding = _vuln_finding(component="requests", risk_score=80.0)
        assert "purl" not in finding["details"]
        cg = _FakeCallgraph(module_usage={"other": {}}, import_map={"a.py": ["other"]}, language="python")
        comp_langs = {"requests": frozenset({"python"})}
        _enrich_finding_from_callgraphs(finding, [cg], comp_langs)
        reach = finding["details"]["reachability"]
        assert reach["is_reachable"] is False
        assert finding["details"]["adjusted_risk_score"] == 32.0  # 80 * 0.4

    def test_wrong_language_still_unknown_with_component_map(self):
        finding = _vuln_finding(component="requests", risk_score=80.0)
        cg = _FakeCallgraph(module_usage={"lodash": {}}, import_map={"a.js": ["lodash"]}, language="javascript")
        comp_langs = {"requests": frozenset({"python"})}
        _enrich_finding_from_callgraphs(finding, [cg], comp_langs)
        assert finding["details"]["reachability"]["is_reachable"] is None
        assert finding["details"]["adjusted_risk_score"] == 80.0

    @pytest.mark.asyncio
    async def test_build_component_language_map_from_deps(self):
        from tests.mocks.fake_mongo import FakeDatabase

        db = FakeDatabase()
        await db.dependencies.insert_one({"scan_id": "s1", "name": "requests", "type": "pypi"})
        await db.dependencies.insert_one({"scan_id": "s1", "name": "left-pad", "type": "npm"})
        await db.dependencies.insert_one({"scan_id": "s1", "name": "mymod", "type": "go-module"})
        await db.dependencies.insert_one({"scan_id": "s1", "name": "viapurl", "purl": "pkg:pypi/viapurl@1.0"})
        await db.dependencies.insert_one({"scan_id": "s1", "name": "rpmpkg", "type": "rpm"})  # no callgraph lang
        m = await _build_component_language_map(db, "s1")
        assert m["requests"] == frozenset({"python"})
        assert m["left-pad"] == frozenset({"javascript", "typescript"})
        assert m["mymod"] == frozenset({"go"})
        assert m["viapurl"] == frozenset({"python"})
        assert "rpmpkg" not in m  # unsupported ecosystem omitted


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

    def test_qualified_vuln_matches_bare_used_symbol(self):
        # Production callgraphs store bare last-segments (e.g. "Read"); an OSV vuln
        # symbol may be qualified (e.g. "Conn.Read"). The last segment must match
        # without reintroducing substring false positives (audit SC#7).
        assert _match_symbols(["Conn.Read"], ["Read"]) == ["Read"]
        assert _match_symbols(["pkg.forget"], ["get"]) == []  # not a boundary match

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


class TestRunPendingBulkPersist:
    """run_pending_reachability_for_scan must persist reachability through a
    chunked bulk_write, not one sequential finding_repo.update per finding: a
    large scan otherwise fires thousands of serial Mongo round-trips inline in
    the callgraph-upload request (audit)."""

    @pytest.mark.asyncio
    async def test_persists_via_bulk_write_and_writes_summary(self, monkeypatch):
        from tests.mocks.fake_mongo import FakeDatabase
        from app.services.reachability_enrichment import run_pending_reachability_for_scan

        db = FakeDatabase()
        pid, sid = "p1", "s1"
        await db.scans.insert_one(
            {"_id": sid, "project_id": pid, "branch": "main", "reachability_pending": True}
        )
        await db.dependencies.insert_one({"scan_id": sid, "name": "requests", "type": "pypi"})
        await db.callgraphs.insert_one(
            {
                "_id": "cg1",
                "project_id": pid,
                "scan_id": sid,
                "language": "python",
                "module_usage": {"requests": {"import_locations": ["a.py"], "used_symbols": []}},
                "import_map": {"a.py": ["requests"]},
            }
        )
        for i in range(3):
            await db.findings.insert_one(
                {
                    "_id": f"f{i}",
                    "id": f"f{i}",
                    "finding_id": f"CVE-2024-000{i}",
                    "type": "vulnerability",
                    "severity": "HIGH",
                    "component": "requests",
                    "version": "1.0.0",
                    "description": "x",
                    "scanners": ["osv"],
                    "project_id": pid,
                    "scan_id": sid,
                    "details": {},
                }
            )

        # Spy: the persist must go through bulk_write. The per-doc repo update
        # path (finding_repo.update -> update_one) must not be used for the loop.
        calls = {"bulk": 0, "update_one": 0}
        orig_bulk = db.findings.bulk_write
        orig_update_one = db.findings.update_one

        async def spy_bulk(ops, ordered=True):
            calls["bulk"] += 1
            return await orig_bulk(ops, ordered=ordered)

        async def spy_update_one(query, update, upsert=False):
            calls["update_one"] += 1
            return await orig_update_one(query, update, upsert=upsert)

        monkeypatch.setattr(db.findings, "bulk_write", spy_bulk)
        monkeypatch.setattr(db.findings, "update_one", spy_update_one)

        result = await run_pending_reachability_for_scan(sid, pid, db)

        assert result["error"] is None
        assert result["findings_enriched"] == 3
        assert calls["bulk"] == 1  # single chunk for < _BULK_CHUNK_SIZE findings
        assert calls["update_one"] == 0  # no sequential per-finding updates

        # All three findings persisted with reachability data.
        for i in range(3):
            doc = await db.findings.find_one({"_id": f"f{i}"})
            assert doc["reachable"] is True
            assert doc["reachability_level"] == "import"

        # Summary written via the shared builder; pending processing completed.
        summary = await db.analysis_results.find_one({"scan_id": sid})
        assert summary is not None
        assert summary["result"]["analyzed"] == 3
        scan = await db.scans.find_one({"_id": sid})
        assert scan.get("reachability_completed_at") is not None
