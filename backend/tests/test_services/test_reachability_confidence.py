"""Tests for is_high_confidence_reachable — the gate distinguishing solid 'function actually called' evidence from import-only heuristics."""

import copy

import pytest

from app.api.v1.helpers.callgraph import parse_generic_format
from app.core.constants import REACHABILITY_HIGH_CONFIDENCE_THRESHOLD, REACHABILITY_LEVEL_IMPORT
from app.schemas.finding_details import ReachabilityInfo
from app.schemas.projections import CallgraphMinimal
from app.services.analysis.stats import build_reachability_summary
from app.services.reachability_enrichment import (
    _enrich_finding_from_callgraphs,
    _match_symbols,
    _prepare_callgraph,
    build_component_language_map,
    enrich_findings_with_reachability,
    is_high_confidence_reachable,
    reachability_set_fields,
    store_reachability,
)


class TestIsHighConfidenceReachable:
    def test_reachable_with_high_confidence_returns_true(self):
        assert is_high_confidence_reachable(True, 0.9) is True

    def test_reachable_at_threshold_returns_true(self):
        # Inclusive boundary: a finding exactly on the threshold is high-confidence.
        assert is_high_confidence_reachable(True, REACHABILITY_HIGH_CONFIDENCE_THRESHOLD) is True

    def test_reachable_below_threshold_returns_false(self):
        # Imported-but-no-symbol-info matches sit at 0.5; they must not feed headline reachable counts.
        assert is_high_confidence_reachable(True, 0.5) is False

    def test_unreachable_returns_false_regardless_of_confidence(self):
        assert is_high_confidence_reachable(False, 0.99) is False

    def test_missing_is_reachable_returns_false(self):
        assert is_high_confidence_reachable(None, 0.9) is False

    def test_missing_confidence_returns_false(self):
        assert is_high_confidence_reachable(True, None) is False


class TestPendingSummaryTiers:
    """The persisted pending summary must map analysis_level (none/import/symbol) onto the display tiers (confirmed/likely/unreachable)."""

    @staticmethod
    def _f(_id, reachable, level):
        return {
            "finding_id": _id,
            "component": _id,
            "version": "1",
            "severity": "HIGH",
            "details": {"reachability": {"is_reachable": reachable, "analysis_level": level}},
        }

    def test_levels_bucketed_by_display_tier(self):
        findings = [
            self._f("a", True, "symbol"),
            self._f("b", True, "import"),
            self._f("c", False, "none"),
        ]
        cg = [_callgraph()]
        summary = build_reachability_summary(findings, cg)
        levels = summary["reachability_levels"]
        assert levels["confirmed"] == 1
        assert levels["likely"] == 1
        assert levels["unreachable"] == 1
        assert levels["unknown"] == 0

    def test_shared_summary_includes_high_confidence_flag(self):
        # The canonical builder includes is_high_confidence.
        findings = [self._f("a", True, "symbol")]
        cg = [_callgraph()]
        summary = build_reachability_summary(findings, cg)
        assert "is_high_confidence" in summary["reachable_vulnerabilities"][0]

    @pytest.mark.parametrize("confidence", [True, "0.9"], ids=["bool", "string"])
    def test_a_non_numeric_confidence_is_not_high_confidence(self, confidence):
        finding = self._f("a", True, "symbol")
        finding["details"]["reachability"]["confidence_score"] = confidence
        cg = [_callgraph()]
        summary = build_reachability_summary([finding], cg)
        assert summary["reachable_vulnerabilities"][0]["is_high_confidence"] is False


class TestImportMatchingUsesWholePackageKeys:
    """Stored module keys are whole packages, so a key that only starts with the package name is another package."""

    @pytest.mark.parametrize(
        ("component", "imported", "language"),
        [
            pytest.param("lodash", "lodash.debounce", "javascript", id="npm_dotted_sibling"),
            pytest.param("underscore", "underscore.string", "javascript", id="npm_dotted_sibling_2"),
            pytest.param("github.com/golang-jwt/jwt", "github.com/golang-jwt/jwt/v4", "go", id="go_major_version"),
            pytest.param("cloud.google.com/go", "cloud.google.com/go/storage", "go", id="go_nested_module"),
        ],
    )
    def test_a_sibling_package_import_leaves_the_package_unreachable(self, component, imported, language):
        finding = _vuln_finding(component=component)
        prepared = _prepared(_usage(imported, "a.src"), language=language, analyzed_modules=[component, imported])

        _enrich_finding_from_callgraphs(finding, [prepared], {component: [("1.0.0", frozenset({language}), False)]})

        assert finding["details"]["reachability"]["is_reachable"] is False

    @pytest.mark.parametrize(
        ("component", "imported", "language"),
        [
            pytest.param("lodash", "lodash/merge", "javascript", id="npm_subpath"),
            pytest.param("requests", "requests.sessions", "python", id="python_submodule"),
        ],
    )
    def test_a_subpath_import_counts_for_its_package(self, component, imported, language):
        module_usage = parse_generic_format({"imports": [{"module": imported, "file": "a.src"}]}, language).module_usage
        prepared = _prepared({key: usage.model_dump() for key, usage in module_usage.items()}, language=language)
        finding = _vuln_finding(component=component)

        _enrich_finding_from_callgraphs(finding, [prepared], {})

        assert finding["details"]["reachability"]["import_locations"] == ["a.src"]


class TestEcosystemFromDependencyMap:
    """Real vulnerability findings carry no details.purl, so the ecosystem gate must derive it from the scan's dependencies, not details.purl."""

    def test_downweight_without_purl_via_component_map(self):
        # Real-shape finding: no details.purl. Ecosystem comes from the dep map.
        finding = _vuln_finding(component="requests", risk_score=80.0)
        assert "purl" not in finding["details"]
        cg = _prepared(
            module_usage=_usage("other", "a.py"),
            language="python",
            analyzed_modules=["requests", "other"],
        )
        comp_langs = {"requests": [("1.0.0", frozenset({"python"}), False)]}
        _enrich_finding_from_callgraphs(finding, [cg], comp_langs)
        reach = finding["details"]["reachability"]
        assert reach["is_reachable"] is False
        assert finding["details"]["adjusted_risk_score"] == 32.0  # 80 * 0.4

    def test_wrong_language_still_unknown_with_component_map(self):
        finding = _vuln_finding(component="requests", risk_score=80.0)
        cg = _prepared(
            module_usage=_usage("lodash", "a.js"),
            language="javascript",
            analyzed_modules=["lodash", "requests"],
        )
        comp_langs = {"requests": [("1.0.0", frozenset({"python"}), False)]}
        _enrich_finding_from_callgraphs(finding, [cg], comp_langs)
        assert finding["details"]["reachability"]["is_reachable"] is None
        assert finding["details"]["adjusted_risk_score"] == 80.0

    @pytest.mark.asyncio
    async def test_build_component_language_map_from_deps(self):
        from tests.mocks.fake_mongo import FakeDatabase

        db = FakeDatabase()
        await db.dependencies.insert_one({"scan_id": "s1", "name": "requests", "version": "2.31.0", "type": "pypi"})
        await db.dependencies.insert_one({"scan_id": "s1", "name": "left-pad", "version": "1.3.0", "type": "npm"})
        await db.dependencies.insert_one({"scan_id": "s1", "name": "mymod", "version": "v1.0.0", "type": "golang"})
        await db.dependencies.insert_one({"scan_id": "s1", "name": "viapurl", "purl": "pkg:pypi/viapurl@1.0"})
        await db.dependencies.insert_one({"scan_id": "s1", "name": "rpmpkg", "type": "rpm"})  # no callgraph lang
        await db.dependencies.insert_one(
            {
                "scan_id": "s1",
                "name": "certifi",
                "version": "2024.7.4",
                "type": "pypi",
                "direct": False,
                "direct_inferred": False,
            }
        )
        m = await build_component_language_map(db, "s1")
        assert m["requests"] == [("2.31.0", frozenset({"python"}), False)]
        assert m["left-pad"] == [("1.3.0", frozenset({"javascript", "typescript"}), False)]
        assert m["mymod"] == [("v1.0.0", frozenset({"go"}), False)]
        assert m["viapurl"] == [("", frozenset({"python"}), False)]
        assert "rpmpkg" not in m  # unsupported ecosystem omitted
        assert m["certifi"] == [("2024.7.4", frozenset({"python"}), True)]


class TestMatchSymbols:
    """Symbol matching must be conservative: a spurious match falsely confirms reachability and boosts risk, so substring matching is unacceptable."""

    def test_exact_match(self):
        assert _match_symbols(["SSL_read"], ["SSL_read"]) == ["SSL_read"]

    def test_case_insensitive_exact_match(self):
        assert _match_symbols(["Foo"], ["foo"]) == ["foo"]

    def test_qualified_call_boundary_matches(self):
        # method chaining / qualified usage: "_.template" ends with ".template"
        assert _match_symbols(["template"], ["_.template"]) == ["_.template"]
        assert _match_symbols(["SSL_read"], ["openssl.SSL_read"]) == ["openssl.SSL_read"]

    def test_qualified_vuln_matches_bare_used_symbol(self):
        # Callgraphs store bare last-segments (e.g. "Read"); a qualified vuln symbol (e.g. "Conn.Read") must match on last segment without substring false positives.
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


def _callgraph(module_usage=None, language="python", analyzed_modules=None):
    """The projection production reads a stored callgraph through."""
    return CallgraphMinimal(
        _id="cg-1", module_usage=module_usage or {}, language=language, analyzed_modules=analyzed_modules or []
    )


def _prepared(module_usage=None, language="python", analyzed_modules=None):
    return _prepare_callgraph(_callgraph(module_usage, language, analyzed_modules))


def _usage(module, location, symbols=()):
    return {module: {"module": module, "import_locations": [location], "used_symbols": list(symbols)}}


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
        """A package inside the coverage universe but absent from the graph is not reachable -> adjusted = base * 0.4."""
        finding = _vuln_finding(component="not-imported-pkg", risk_score=80.0)
        cg = _prepared(
            module_usage=_usage("other", "a.py"),
            language="python",
            analyzed_modules=["not-imported-pkg", "other"],
        )
        _enrich_finding_from_callgraphs(finding, [cg], {"not-imported-pkg": [("1.0.0", frozenset({"python"}), False)]})
        assert finding["details"]["reachability"]["is_reachable"] is False
        # 80 * 0.4 == 32.0
        assert finding["details"]["adjusted_risk_score"] == 32.0
        assert finding["details"]["adjusted_risk_score"] < finding["details"]["risk_score"]


class TestReachabilityFailClosed:
    """Absence of evidence is not evidence of unreachability: a package missing from a callgraph that doesn't cover its ecosystem (or unknown ecosystem) must be recorded as unknown, not down-weighted."""

    def test_wrong_language_callgraph_does_not_downweight(self):
        # pypi finding, but only a JS callgraph analyzed -> absence is meaningless.
        finding = _vuln_finding(component="requests", risk_score=80.0)
        cg = _prepared(
            module_usage=_usage("lodash", "a.js"),
            language="javascript",
            analyzed_modules=["lodash", "requests"],
        )
        _enrich_finding_from_callgraphs(finding, [cg], {"requests": [("1.0.0", frozenset({"python"}), False)]})
        reach = finding["details"]["reachability"]
        assert reach["is_reachable"] is None
        assert "No python callgraph was uploaded" in reach["message"]
        assert finding["details"]["adjusted_risk_score"] == 80.0  # identity, no x0.4

    def test_unknown_ecosystem_does_not_downweight(self):
        # Package absent from the scan's dependency map -> ecosystem unknown -> no penalty.
        finding = _vuln_finding(component="mystery", risk_score=80.0)
        cg = _prepared(
            module_usage=_usage("other", "a.py"),
            language="python",
            analyzed_modules=["other", "mystery"],
        )
        _enrich_finding_from_callgraphs(finding, [cg], {})
        reach = finding["details"]["reachability"]
        assert reach["is_reachable"] is None
        assert "no callgraph tool supports" in reach["message"]
        assert finding["details"]["adjusted_risk_score"] == 80.0

    def test_empty_coverage_universe_cannot_falsify(self):
        # The producer published no analyzed_modules -> it inspected nothing we can name.
        finding = _vuln_finding(component="requests", risk_score=80.0)
        cg = _prepared(module_usage=_usage("other", "a.py"), language="python")
        _enrich_finding_from_callgraphs(finding, [cg], {"requests": [("1.0.0", frozenset({"python"}), False)]})
        reach = finding["details"]["reachability"]
        assert reach["is_reachable"] is None
        assert "published no coverage universe" in reach["message"]
        assert finding["details"]["adjusted_risk_score"] == 80.0

    def test_package_outside_coverage_universe_cannot_falsify(self):
        # The producer resolved a universe, but never resolved this package.
        finding = _vuln_finding(component="requests", risk_score=80.0)
        cg = _prepared(module_usage=_usage("other", "a.py"), language="python", analyzed_modules=["other"])
        _enrich_finding_from_callgraphs(finding, [cg], {"requests": [("1.0.0", frozenset({"python"}), False)]})
        reach = finding["details"]["reachability"]
        assert reach["is_reachable"] is None
        assert "outside the coverage universe" in reach["message"]
        assert finding["details"]["adjusted_risk_score"] == 80.0

    def test_covering_language_still_downweights(self):
        # npm finding inside the JS coverage universe but unimported -> genuine unreachable -> x0.4.
        finding = _vuln_finding(component="left-pad", risk_score=80.0)
        cg = _prepared(
            module_usage=_usage("lodash", "a.js"),
            language="javascript",
            analyzed_modules=["lodash", "left-pad"],
        )
        _enrich_finding_from_callgraphs(
            finding, [cg], {"left-pad": [("1.0.0", frozenset({"javascript", "typescript"}), False)]}
        )
        reach = finding["details"]["reachability"]
        assert reach["is_reachable"] is False
        assert finding["details"]["adjusted_risk_score"] == 32.0

    def test_kev_finding_is_never_downweighted_at_import_level(self):
        # A KEV false negative ends the feature: absence of an import is too weak to de-prioritise.
        finding = _vuln_finding(component="left-pad", risk_score=80.0)
        finding["details"]["in_kev"] = True
        cg = _prepared(
            module_usage=_usage("lodash", "a.js"),
            language="javascript",
            analyzed_modules=["lodash", "left-pad"],
        )
        _enrich_finding_from_callgraphs(
            finding, [cg], {"left-pad": [("1.0.0", frozenset({"javascript", "typescript"}), False)]}
        )
        reach = finding["details"]["reachability"]
        assert reach["is_reachable"] is False
        assert reach["analysis_level"] == "import"
        assert finding["details"]["adjusted_risk_score"] == 80.0

    def test_qualified_component_resolves_to_the_bare_usage_key(self):
        """Gate and verdict resolve the alias through the same lookup, so a resolved package can't be stamped 'not imported'."""
        finding = _vuln_finding(component="org.example:left-pad", risk_score=80.0)
        cg = _prepared(
            module_usage=_usage("left-pad", "a.js"),
            language="javascript",
            analyzed_modules=["left-pad"],
        )
        _enrich_finding_from_callgraphs(
            finding, [cg], {"org.example:left-pad": [("1.0.0", frozenset({"javascript"}), False)]}
        )
        reach = finding["details"]["reachability"]
        assert reach["is_reachable"] is True
        assert reach["import_locations"] == ["a.js"]
        assert finding["details"]["adjusted_risk_score"] == 80.0

    def test_symbol_reachable_persists_boosted_adjusted_score(self):
        """A matched vulnerable symbol -> confirmed -> adjusted = base * 1.1."""
        finding = _vuln_finding(component="requests", risk_score=80.0)
        # Symbols only ever come from the structured OSV payload, never from prose.
        finding["details"]["vulnerabilities"] = [{"id": "CVE-2024-0001", "ecosystem_specific": {"symbols": ["get"]}}]
        _enrich_finding_from_callgraphs(finding, [_prepared(_usage("requests", "a.py", symbols=["get"]))], {})
        reach = finding["details"]["reachability"]
        assert reach["is_reachable"] is True
        assert reach["analysis_level"] == "symbol"
        assert reach["matched_symbols"] == ["get"]
        assert finding["details"]["adjusted_risk_score"] == 88.0

    def test_import_only_reachable_is_identity(self):
        """Imported but no extracted symbols -> import-level reachable -> identity (no boost)."""
        finding = _vuln_finding(component="requests", risk_score=80.0)
        _enrich_finding_from_callgraphs(finding, [_prepared(_usage("requests", "a.py"))], {})
        reach = finding["details"]["reachability"]
        assert reach["is_reachable"] is True
        assert reach["analysis_level"] == "import"
        assert finding["details"]["adjusted_risk_score"] == finding["details"]["risk_score"]


class TestPureEnrichmentEntryPoint:
    """The reachability loop must run without a database, callgraph repository or scan id."""

    def test_enriches_only_vulnerability_findings_and_returns_the_count(self):
        vuln = _vuln_finding(component="requests", risk_score=80.0)
        secret = {"type": "secret", "component": "config/aws.env", "details": {}}
        cg = _callgraph(module_usage=_usage("requests", "app/client.py"), language="python")

        enriched = enrich_findings_with_reachability(
            [vuln, secret], [cg], {"requests": [("1.0.0", frozenset({"python"}), False)]}
        )

        assert enriched == 1
        assert vuln["reachable"] is True
        assert "reachability" not in secret["details"]

    def test_mirrors_the_verdict_to_the_top_level_fields(self):
        vuln = _vuln_finding(component="requests", risk_score=80.0)
        cg = _callgraph(module_usage=_usage("requests", "app/client.py"), language="python")

        enrich_findings_with_reachability([vuln], [cg], {"requests": [("1.0.0", frozenset({"python"}), False)]})

        assert vuln["reachability_level"] == REACHABILITY_LEVEL_IMPORT


class TestReachabilitySetFields:
    @pytest.mark.parametrize("is_reachable", [True, False])
    def test_names_every_field_store_reachability_writes(self, is_reachable):
        finding = _vuln_finding()
        before = copy.deepcopy(finding)

        store_reachability(finding, ReachabilityInfo(is_reachable=is_reachable, analysis_level="import"))

        written = {key for key in finding if key != "details" and finding[key] != before.get(key)}
        written |= {
            f"details.{key}" for key, value in finding["details"].items() if value != before["details"].get(key)
        }
        assert written == set(reachability_set_fields(finding))


class TestRunPendingBulkPersist:
    """run_pending_reachability_for_scan must persist via a chunked bulk_write, not one sequential update per finding."""

    @pytest.mark.asyncio
    async def test_persists_via_bulk_write_and_writes_summary(self, monkeypatch):
        from app.services.reachability_enrichment import run_pending_reachability_for_scan
        from tests.mocks.fake_mongo import FakeDatabase

        db = FakeDatabase()
        pid, sid = "p1", "s1"
        await db.scans.insert_one({"_id": sid, "project_id": pid, "branch": "main", "reachability_pending": True})
        await db.dependencies.insert_one({"scan_id": sid, "name": "requests", "type": "pypi"})
        await db.callgraphs.insert_one(
            {
                "_id": "cg1",
                "project_id": pid,
                "scan_id": sid,
                "language": "python",
                "module_usage": {"requests": {"module": "requests", "import_locations": ["a.py"]}},
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

        # The persist must go through bulk_write, not per-doc update_one.
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

        await run_pending_reachability_for_scan(sid, pid, db)

        assert calls["bulk"] == 1
        assert calls["update_one"] == 0

        # All three findings persisted with reachability data.
        for i in range(3):
            doc = await db.findings.find_one({"_id": f"f{i}"})
            assert doc["reachable"] is True
            assert doc["reachability_level"] == "import"

        summary = await db.analysis_results.find_one({"scan_id": sid})
        assert summary is not None
        assert summary["result"]["analyzed"] == 3
        scan = await db.scans.find_one({"_id": sid})
        assert scan["stats"]["reachability"]["analyzed_count"] == 3

    @pytest.mark.asyncio
    async def test_second_language_callgraph_still_runs(self):
        """A multi-language repo uploads one callgraph per language; the later ones must not be ignored."""
        from app.services.reachability_enrichment import run_pending_reachability_for_scan
        from tests.mocks.fake_mongo import FakeDatabase

        db = FakeDatabase()
        pid, sid = "p1", "s1"
        # Every upload flags the scan again, even after the first language cleared it.
        await db.scans.insert_one({"_id": sid, "project_id": pid, "branch": "main", "reachability_pending": True})
        await db.dependencies.insert_one({"scan_id": sid, "name": "left-pad", "type": "npm"})
        await db.callgraphs.insert_one(
            {
                "_id": "cg-js",
                "project_id": pid,
                "scan_id": sid,
                "language": "javascript",
                "analyzed_modules": ["left-pad"],
                "module_usage": {"left-pad": {"import_locations": ["a.js"], "used_symbols": []}},
            }
        )
        await db.findings.insert_one(
            {
                "_id": "f0",
                "id": "f0",
                "finding_id": "CVE-2024-0001",
                "type": "vulnerability",
                "severity": "HIGH",
                "component": "left-pad",
                "version": "1.0.0",
                "description": "x",
                "scanners": ["osv"],
                "project_id": pid,
                "scan_id": sid,
                "details": {},
            }
        )

        await run_pending_reachability_for_scan(sid, pid, db)

        doc = await db.findings.find_one({"_id": "f0"})
        assert doc["reachable"] is True
