"""Tests for analysis stats helper functions."""

from datetime import datetime, timezone

import pytest

from app.services.analysis.stats import (
    _format_datetime,
    build_epss_kev_summary,
    build_reachability_summary,
    calculate_comprehensive_stats,
)
from tests.mocks.fake_mongo import FakeDatabase

# ---------------------------------------------------------------------------
# _format_datetime
# ---------------------------------------------------------------------------


class TestFormatDatetime:
    def test_none_returns_none(self):
        assert _format_datetime(None) is None

    def test_datetime_returns_isoformat(self):
        dt = datetime(2024, 6, 15, 12, 30, 0, tzinfo=timezone.utc)
        result = _format_datetime(dt)
        assert result == dt.isoformat()

    def test_string_passthrough(self):
        assert _format_datetime("2024-01-01T00:00:00Z") == "2024-01-01T00:00:00Z"

    def test_empty_string_returns_none(self):
        assert _format_datetime("") is None

    def test_int_returns_str(self):
        assert _format_datetime(12345) == "12345"


# ---------------------------------------------------------------------------
# build_epss_kev_summary  –  helpers
# ---------------------------------------------------------------------------


def _make_finding(
    finding_id="CVE-2024-0001",
    component="pkg",
    version="1.0.0",
    epss_score=None,
    in_kev=False,
    kev_due_date=None,
    kev_ransomware_use=False,
    exploit_maturity="unknown",
    risk_score=None,
):
    details = {"exploit_maturity": exploit_maturity}
    if epss_score is not None:
        details["epss_score"] = epss_score
    if in_kev:
        details["in_kev"] = True
    if kev_due_date is not None:
        details["kev_due_date"] = kev_due_date
    if kev_ransomware_use:
        details["kev_ransomware_use"] = True
    if risk_score is not None:
        details["risk_score"] = risk_score
    return {
        "finding_id": finding_id,
        "component": component,
        "version": version,
        "details": details,
    }


# ---------------------------------------------------------------------------
# build_epss_kev_summary
# ---------------------------------------------------------------------------


class TestBuildEpssKevSummaryEmpty:
    def test_empty_list_returns_zero_totals(self):
        result = build_epss_kev_summary([])
        assert result["total_vulnerabilities"] == 0
        assert result["epss_enriched"] == 0
        assert result["kev_matches"] == 0
        assert result["kev_ransomware"] == 0

    def test_empty_list_scores_are_none(self):
        result = build_epss_kev_summary([])
        assert result["avg_epss_score"] is None
        assert result["max_epss_score"] is None
        assert result["avg_risk_score"] is None
        assert result["max_risk_score"] is None

    def test_empty_list_has_timestamp(self):
        result = build_epss_kev_summary([])
        assert result["timestamp"] is not None


class TestBuildEpssKevSummaryEpss:
    def test_single_finding_with_epss(self):
        findings = [_make_finding(epss_score=0.05)]
        result = build_epss_kev_summary(findings)
        assert result["epss_enriched"] == 1
        assert result["total_vulnerabilities"] == 1

    def test_epss_high_bucket(self):
        findings = [_make_finding(epss_score=0.5)]
        result = build_epss_kev_summary(findings)
        assert result["epss_scores"]["high"] == 1
        assert result["epss_scores"]["medium"] == 0
        assert result["epss_scores"]["low"] == 0

    def test_epss_medium_bucket(self):
        findings = [_make_finding(epss_score=0.05)]
        result = build_epss_kev_summary(findings)
        assert result["epss_scores"]["medium"] == 1

    def test_epss_low_bucket(self):
        findings = [_make_finding(epss_score=0.001)]
        result = build_epss_kev_summary(findings)
        assert result["epss_scores"]["low"] == 1

    def test_epss_boundary_high(self):
        # 0.1 is inclusive in the high bucket
        findings = [_make_finding(epss_score=0.1)]
        result = build_epss_kev_summary(findings)
        assert result["epss_scores"]["high"] == 1
        assert result["epss_scores"]["medium"] == 0

    def test_epss_boundary_medium(self):
        # 0.01 is inclusive in the medium bucket
        findings = [_make_finding(epss_score=0.01)]
        result = build_epss_kev_summary(findings)
        assert result["epss_scores"]["medium"] == 1
        assert result["epss_scores"]["low"] == 0

    def test_avg_epss_score(self):
        findings = [
            _make_finding(finding_id="CVE-1", epss_score=0.2),
            _make_finding(finding_id="CVE-2", epss_score=0.4),
        ]
        result = build_epss_kev_summary(findings)
        assert result["avg_epss_score"] == round((0.2 + 0.4) / 2, 4)

    def test_max_epss_score(self):
        findings = [
            _make_finding(finding_id="CVE-1", epss_score=0.1),
            _make_finding(finding_id="CVE-2", epss_score=0.9),
        ]
        result = build_epss_kev_summary(findings)
        assert result["max_epss_score"] == 0.9

    def test_finding_without_epss_not_counted(self):
        findings = [_make_finding(epss_score=None)]
        result = build_epss_kev_summary(findings)
        assert result["epss_enriched"] == 0
        assert result["avg_epss_score"] is None


class TestBuildEpssKevSummaryKev:
    def test_kev_match_counted(self):
        findings = [_make_finding(in_kev=True)]
        result = build_epss_kev_summary(findings)
        assert result["kev_matches"] == 1

    def test_kev_detail_recorded(self):
        findings = [_make_finding(finding_id="CVE-2024-9999", component="openssl", in_kev=True)]
        result = build_epss_kev_summary(findings)
        assert len(result["kev_details"]) == 1
        detail = result["kev_details"][0]
        assert detail["cve"] == "CVE-2024-9999"
        assert detail["component"] == "openssl"

    def test_kev_due_date_propagated(self):
        findings = [_make_finding(in_kev=True, kev_due_date="2024-12-01")]
        result = build_epss_kev_summary(findings)
        assert result["kev_details"][0]["due_date"] == "2024-12-01"

    def test_kev_ransomware_counted(self):
        findings = [_make_finding(in_kev=True, kev_ransomware_use=True)]
        result = build_epss_kev_summary(findings)
        assert result["kev_ransomware"] == 1
        assert result["kev_details"][0]["ransomware"] is True

    def test_kev_no_ransomware(self):
        findings = [_make_finding(in_kev=True, kev_ransomware_use=False)]
        result = build_epss_kev_summary(findings)
        assert result["kev_ransomware"] == 0


class TestBuildEpssKevSummaryRisk:
    def test_risk_score_average(self):
        findings = [
            _make_finding(finding_id="CVE-1", risk_score=80.0),
            _make_finding(finding_id="CVE-2", risk_score=60.0),
        ]
        result = build_epss_kev_summary(findings)
        assert result["avg_risk_score"] == round((80.0 + 60.0) / 2, 1)

    def test_risk_score_max(self):
        findings = [
            _make_finding(finding_id="CVE-1", risk_score=30.0),
            _make_finding(finding_id="CVE-2", risk_score=95.0),
        ]
        result = build_epss_kev_summary(findings)
        assert result["max_risk_score"] == 95.0

    def test_high_risk_cve_above_threshold(self):
        findings = [_make_finding(risk_score=80.0, component="openssl", version="3.0.0")]
        result = build_epss_kev_summary(findings)
        assert len(result["high_risk_cves"]) == 1
        cve = result["high_risk_cves"][0]
        assert cve["risk_score"] == 80.0
        assert cve["component"] == "openssl"
        assert cve["version"] == "3.0.0"

    def test_high_risk_cve_at_threshold_excluded(self):
        # threshold is strictly greater than 70.0
        findings = [_make_finding(risk_score=70.0)]
        result = build_epss_kev_summary(findings)
        assert len(result["high_risk_cves"]) == 0

    def test_high_risk_cves_sorted_descending(self):
        findings = [
            _make_finding(finding_id="CVE-1", risk_score=75.0),
            _make_finding(finding_id="CVE-2", risk_score=95.0),
            _make_finding(finding_id="CVE-3", risk_score=85.0),
        ]
        result = build_epss_kev_summary(findings)
        scores = [c["risk_score"] for c in result["high_risk_cves"]]
        assert scores == sorted(scores, reverse=True)

    def test_high_risk_cves_limited_to_20(self):
        findings = [_make_finding(finding_id=f"CVE-{i}", risk_score=71.0 + i) for i in range(25)]
        result = build_epss_kev_summary(findings)
        assert len(result["high_risk_cves"]) == 20

    def test_no_risk_scores_gives_none(self):
        findings = [_make_finding(risk_score=None)]
        result = build_epss_kev_summary(findings)
        assert result["avg_risk_score"] is None
        assert result["max_risk_score"] is None


class TestBuildEpssKevSummaryExploitMaturity:
    def test_known_maturity_counted(self):
        findings = [_make_finding(exploit_maturity="weaponized")]
        result = build_epss_kev_summary(findings)
        assert result["exploit_maturity"]["weaponized"] == 1

    def test_unknown_maturity_default(self):
        findings = [{"details": {}, "component": "pkg"}]
        result = build_epss_kev_summary(findings)
        assert result["exploit_maturity"]["unknown"] == 1

    def test_unrecognised_maturity_ignored(self):
        findings = [_make_finding(exploit_maturity="invented_level")]
        result = build_epss_kev_summary(findings)
        total = sum(result["exploit_maturity"].values())
        assert total == 0


def _aggregated_vuln_finding(entries, *, in_kev=True, risk_score=None, aliases=None):
    """Shape the engine actually persists: finding_id is ``component:version``, the CVE ids
    live on the nested ``details.vulnerabilities`` entries."""
    details = {
        "exploit_maturity": "unknown",
        "vulnerabilities": entries,
    }
    if in_kev:
        details["in_kev"] = True
        details["kev_due_date"] = "2026-08-07"
    if risk_score is not None:
        details["risk_score"] = risk_score
    return {
        "_id": "5b7d0e1f-0000-5000-8000-000000000001",
        "id": "tomcat-embed-core:10.1.41",
        "finding_id": "tomcat-embed-core:10.1.41",
        "component": "tomcat-embed-core",
        "version": "10.1.41",
        "aliases": aliases or [],
        "details": details,
    }


class TestKevRowsCarryRealCveIds:
    """K23: KEV and high-risk rows must never show the component:version finding_id."""

    def test_kev_row_uses_the_nested_entry_cve(self):
        finding = _aggregated_vuln_finding(
            [
                {
                    "id": "CVE-2025-66614",
                    "resolved_cve": "CVE-2026-24880",
                    "severity": "HIGH",
                    "in_kev": True,
                    "kev_due_date": "2026-08-07",
                    "kev_ransomware_use": False,
                }
            ]
        )
        result = build_epss_kev_summary([finding])
        assert [d["cve"] for d in result["kev_details"]] == ["CVE-2025-66614"]
        assert result["kev_details"][0]["due_date"] == "2026-08-07"

    def test_one_row_per_known_exploited_cve(self):
        finding = _aggregated_vuln_finding(
            [
                {"id": "CVE-2025-66614", "in_kev": True, "kev_due_date": "2026-08-07"},
                {"id": "CVE-2025-11111", "in_kev": True, "kev_ransomware_use": True},
                {"id": "CVE-2025-22222"},
            ]
        )
        result = build_epss_kev_summary([finding])
        assert [d["cve"] for d in result["kev_details"]] == ["CVE-2025-66614", "CVE-2025-11111"]
        assert result["kev_matches"] == 2
        assert result["kev_ransomware"] == 1

    def test_ghsa_entry_without_a_cve_keeps_the_advisory_id(self):
        finding = _aggregated_vuln_finding([{"id": "GHSA-9f52-rjqv-25qv", "in_kev": True}])
        result = build_epss_kev_summary([finding])
        assert result["kev_details"][0]["cve"] == "GHSA-9f52-rjqv-25qv"

    def test_kev_flag_only_on_the_document_falls_back_to_its_alias(self):
        finding = _aggregated_vuln_finding(
            [{"id": "GHSA-other", "severity": "HIGH"}],
            aliases=["CVE-2025-77777"],
        )
        result = build_epss_kev_summary([finding])
        assert result["kev_details"][0]["cve"] == "CVE-2025-77777"

    def test_high_risk_row_uses_the_cve_too(self):
        finding = _aggregated_vuln_finding(
            [{"id": "CVE-2025-66614", "severity": "CRITICAL"}],
            in_kev=False,
            risk_score=91.0,
        )
        result = build_epss_kev_summary([finding])
        assert result["high_risk_cves"][0]["cve"] == "CVE-2025-66614"


class TestBuildEpssKevSummaryFindingId:
    def test_finding_id_preferred_over_id(self):
        finding = _make_finding(finding_id="CVE-PREFERRED", risk_score=80.0)
        finding["id"] = "CVE-FALLBACK"
        result = build_epss_kev_summary([finding])
        assert result["high_risk_cves"][0]["cve"] == "CVE-PREFERRED"

    def test_id_used_as_fallback(self):
        finding = {
            "id": "CVE-FALLBACK",
            "component": "pkg",
            "version": "1.0",
            "details": {"risk_score": 80.0, "exploit_maturity": "unknown"},
        }
        result = build_epss_kev_summary([finding])
        assert result["high_risk_cves"][0]["cve"] == "CVE-FALLBACK"


# ---------------------------------------------------------------------------
# build_reachability_summary  –  helpers
# ---------------------------------------------------------------------------


# Tests use display tiers (confirmed/likely/...); findings persist analysis_level (none/import/symbol), so translate.
_DISPLAY_TIER_TO_ANALYSIS_LEVEL = {
    "confirmed": "symbol",
    "likely": "import",
    "unreachable": "none",
    "unknown": "unknown",
}


def _make_reachable_finding(
    finding_id="CVE-2024-0001",
    component="pkg",
    version="1.0.0",
    severity="HIGH",
    reachable=None,
    reachability_level="unknown",
    reachable_functions=None,
):
    analysis_level = _DISPLAY_TIER_TO_ANALYSIS_LEVEL.get(reachability_level, reachability_level)
    reachability_data: dict = {"analysis_level": analysis_level}
    if reachable is not None:
        reachability_data["is_reachable"] = reachable
    if reachable_functions is not None:
        reachability_data["matched_symbols"] = reachable_functions
    return {
        "finding_id": finding_id,
        "component": component,
        "version": version,
        "severity": severity,
        "details": {"reachability": reachability_data},
    }


def _make_callgraph(language="python", modules=None, total_imports=0, analyzed_modules=None, created_at=None):
    cg = {
        "language": language,
        "module_usage": modules if modules is not None else {},
        "analyzed_modules": analyzed_modules if analyzed_modules is not None else [],
        "total_imports": total_imports,
    }
    if created_at is not None:
        cg["created_at"] = created_at
    return cg


# ---------------------------------------------------------------------------
# build_reachability_summary
# ---------------------------------------------------------------------------


class TestBuildReachabilitySummaryEmpty:
    def test_empty_findings(self):
        result = build_reachability_summary([], [_make_callgraph()], 0)
        assert result["total_vulnerabilities"] == 0
        assert result["analyzed"] == 0
        assert result["reachable_vulnerabilities"] == []
        assert result["unreachable_vulnerabilities"] == []

    def test_empty_findings_has_timestamp(self):
        result = build_reachability_summary([], [_make_callgraph()], 0)
        assert result["timestamp"] is not None


class TestBuildReachabilitySummaryLevels:
    def test_confirmed_level(self):
        findings = [_make_reachable_finding(reachable=True, reachability_level="confirmed")]
        result = build_reachability_summary(findings, [_make_callgraph()], 1)
        assert result["reachability_levels"]["confirmed"] == 1

    def test_likely_level(self):
        findings = [_make_reachable_finding(reachable=True, reachability_level="likely")]
        result = build_reachability_summary(findings, [_make_callgraph()], 1)
        assert result["reachability_levels"]["likely"] == 1

    def test_unknown_level(self):
        findings = [_make_reachable_finding(reachability_level="unknown")]
        result = build_reachability_summary(findings, [_make_callgraph()], 0)
        assert result["reachability_levels"]["unknown"] == 1

    def test_unreachable_level(self):
        findings = [_make_reachable_finding(reachable=False, reachability_level="unreachable")]
        result = build_reachability_summary(findings, [_make_callgraph()], 1)
        assert result["reachability_levels"]["unreachable"] == 1

    def test_multiple_levels_counted(self):
        findings = [
            _make_reachable_finding(finding_id="CVE-1", reachable=True, reachability_level="confirmed"),
            _make_reachable_finding(finding_id="CVE-2", reachable=True, reachability_level="likely"),
            _make_reachable_finding(finding_id="CVE-3", reachable=False, reachability_level="unreachable"),
            _make_reachable_finding(finding_id="CVE-4", reachability_level="unknown"),
        ]
        result = build_reachability_summary(findings, [_make_callgraph()], 3)
        levels = result["reachability_levels"]
        assert levels["confirmed"] == 1
        assert levels["likely"] == 1
        assert levels["unreachable"] == 1
        assert levels["unknown"] == 1


class TestBuildReachabilitySummaryCallgraph:
    def test_language_extracted(self):
        cg = _make_callgraph(language="java")
        result = build_reachability_summary([], [cg], 0)
        assert result["callgraph_info"][0]["language"] == "java"

    def test_module_count(self):
        cg = _make_callgraph(modules={"mod_a": {}, "mod_b": {}})
        result = build_reachability_summary([], [cg], 0)
        assert result["callgraph_info"][0]["total_modules"] == 2

    def test_import_count_uses_persisted_counter(self):
        cg = _make_callgraph(modules={"mod_a": {}}, total_imports=17)
        result = build_reachability_summary([], [cg], 0)
        assert result["callgraph_info"][0]["total_imports"] == 17

    def test_coverage_modules_from_analyzed_modules(self):
        cg = _make_callgraph(analyzed_modules=["requests", "urllib3"])
        result = build_reachability_summary([], [cg], 0)
        assert result["callgraph_info"][0]["coverage_modules"] == 2

    def test_coverage_modules_zero_without_analyzed_modules(self):
        result = build_reachability_summary([], [_make_callgraph()], 0)
        assert result["callgraph_info"][0]["coverage_modules"] == 0

    def test_null_module_usage_is_not_a_crash(self):
        cg = _make_callgraph()
        cg["module_usage"] = None
        result = build_reachability_summary([], [cg], 0)
        assert result["callgraph_info"][0]["total_modules"] == 0

    def test_generated_at_from_datetime(self):
        dt = datetime(2024, 1, 15, 8, 0, 0, tzinfo=timezone.utc)
        cg = _make_callgraph(created_at=dt)
        result = build_reachability_summary([], [cg], 0)
        assert result["callgraph_info"][0]["generated_at"] == dt.isoformat()

    def test_generated_at_none_when_missing(self):
        cg = _make_callgraph()
        result = build_reachability_summary([], [cg], 0)
        assert result["callgraph_info"][0]["generated_at"] is None

    def test_missing_language_defaults_to_unknown(self):
        result = build_reachability_summary([], [{"module_usage": {}}], 0)
        assert result["callgraph_info"][0]["language"] == "unknown"


class TestBuildReachabilitySummaryPartitioning:
    def test_reachable_true_goes_to_reachable_list(self):
        findings = [_make_reachable_finding(reachable=True, reachability_level="confirmed")]
        result = build_reachability_summary(findings, [_make_callgraph()], 1)
        assert len(result["reachable_vulnerabilities"]) == 1
        assert len(result["unreachable_vulnerabilities"]) == 0

    def test_reachable_false_goes_to_unreachable_list(self):
        findings = [_make_reachable_finding(reachable=False, reachability_level="unreachable")]
        result = build_reachability_summary(findings, [_make_callgraph()], 1)
        assert len(result["reachable_vulnerabilities"]) == 0
        assert len(result["unreachable_vulnerabilities"]) == 1

    def test_reachable_none_goes_to_neither_list(self):
        findings = [_make_reachable_finding(reachability_level="unknown")]
        result = build_reachability_summary(findings, [_make_callgraph()], 0)
        assert len(result["reachable_vulnerabilities"]) == 0
        assert len(result["unreachable_vulnerabilities"]) == 0

    def test_vuln_info_fields(self):
        findings = [
            _make_reachable_finding(
                finding_id="CVE-2024-5678",
                component="openssl",
                version="3.0.0",
                severity="CRITICAL",
                reachable=True,
                reachability_level="confirmed",
                reachable_functions=["SSL_read"],
            )
        ]
        result = build_reachability_summary(findings, [_make_callgraph()], 1)
        vuln = result["reachable_vulnerabilities"][0]
        assert vuln["cve"] == "CVE-2024-5678"
        assert vuln["component"] == "openssl"
        assert vuln["version"] == "3.0.0"
        assert vuln["severity"] == "CRITICAL"
        assert vuln["reachability_level"] == "confirmed"
        assert vuln["reachable_functions"] == ["SSL_read"]

    def test_reachable_functions_limited_to_5(self):
        funcs = [f"func_{i}" for i in range(10)]
        findings = [_make_reachable_finding(reachable=True, reachability_level="confirmed", reachable_functions=funcs)]
        result = build_reachability_summary(findings, [_make_callgraph()], 1)
        assert len(result["reachable_vulnerabilities"][0]["reachable_functions"]) == 5


class TestBuildReachabilitySummarySorting:
    def test_reachable_sorted_by_severity_descending(self):
        findings = [
            _make_reachable_finding(finding_id="CVE-1", severity="LOW", reachable=True, reachability_level="confirmed"),
            _make_reachable_finding(
                finding_id="CVE-2", severity="CRITICAL", reachable=True, reachability_level="confirmed"
            ),
            _make_reachable_finding(finding_id="CVE-3", severity="MEDIUM", reachable=True, reachability_level="likely"),
        ]
        result = build_reachability_summary(findings, [_make_callgraph()], 3)
        severities = [v["severity"] for v in result["reachable_vulnerabilities"]]
        assert severities == ["CRITICAL", "MEDIUM", "LOW"]

    def test_unreachable_sorted_by_severity_descending(self):
        findings = [
            _make_reachable_finding(
                finding_id="CVE-1", severity="LOW", reachable=False, reachability_level="unreachable"
            ),
            _make_reachable_finding(
                finding_id="CVE-2", severity="HIGH", reachable=False, reachability_level="unreachable"
            ),
        ]
        result = build_reachability_summary(findings, [_make_callgraph()], 2)
        severities = [v["severity"] for v in result["unreachable_vulnerabilities"]]
        assert severities == ["HIGH", "LOW"]


class TestBuildReachabilitySummaryLimits:
    def test_reachable_limited_to_30(self):
        findings = [
            _make_reachable_finding(
                finding_id=f"CVE-{i}",
                reachable=True,
                reachability_level="confirmed",
            )
            for i in range(35)
        ]
        result = build_reachability_summary(findings, [_make_callgraph()], 35)
        assert len(result["reachable_vulnerabilities"]) == 30
        assert result["reachable_total"] == 35

    def test_unreachable_limited_to_30(self):
        findings = [
            _make_reachable_finding(
                finding_id=f"CVE-{i}",
                reachable=False,
                reachability_level="unreachable",
            )
            for i in range(35)
        ]
        result = build_reachability_summary(findings, [_make_callgraph()], 35)
        assert len(result["unreachable_vulnerabilities"]) == 30
        assert result["unreachable_total"] == 35

    def test_totals_exclude_unanalysed_findings(self):
        findings = [
            _make_reachable_finding(finding_id="CVE-1", reachable=True, reachability_level="confirmed"),
            _make_reachable_finding(finding_id="CVE-2", reachable=False, reachability_level="unreachable"),
            _make_reachable_finding(finding_id="CVE-3", reachability_level="unknown"),
        ]
        result = build_reachability_summary(findings, [_make_callgraph()], 2)
        assert result["reachable_total"] == 1
        assert result["unreachable_total"] == 1

    def test_analyzed_count_passthrough(self):
        result = build_reachability_summary([], [_make_callgraph()], 42)
        assert result["analyzed"] == 42


# calculate_comprehensive_stats: risk_score is a saturating severity-weighted exposure
# score (0-100, monotone in the finding set); adjusted_risk_score shares the same scale
# with per-finding reachability modifiers applied to the weights.

_W5_SCAN = "scan-w5"


def _w5_finding(
    _id,
    severity,
    *,
    risk_score=None,
    adjusted_risk_score=None,
    reachable=None,
    reachability_level="unknown",
    waived=False,
):
    details = {}
    if risk_score is not None:
        details["risk_score"] = risk_score
    if adjusted_risk_score is not None:
        details["adjusted_risk_score"] = adjusted_risk_score
    doc = {
        "_id": _id,
        "finding_id": _id,
        "scan_id": _W5_SCAN,
        "type": "vulnerability",
        "severity": severity,
        "component": "pkg",
        "version": "1.0.0",
        "details": details,
        "waived": waived,
    }
    if reachable is not None:
        doc["reachable"] = reachable
        doc["reachability_level"] = reachability_level
    return doc


async def _seed(findings):
    db = FakeDatabase()
    for f in findings:
        await db.findings.insert_one(f)
    return db


async def _risk_score(findings):
    db = await _seed(findings)
    stats = await calculate_comprehensive_stats(db, _W5_SCAN)
    return stats.risk_score


class TestRiskScoreSaturatingExposure:
    @pytest.mark.asyncio
    async def test_single_critical_score(self):
        # exposure 20 -> 100*20/(20+250) = 7.4
        assert await _risk_score([_w5_finding("c1", "CRITICAL")]) == 7.4

    @pytest.mark.asyncio
    async def test_single_finding_scores_ordered_by_severity(self):
        scores = [await _risk_score([_w5_finding("f", sev)]) for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW")]
        assert scores == sorted(scores, reverse=True)
        assert scores[-1] > 0.0

    @pytest.mark.asyncio
    async def test_score_saturates_below_100(self):
        findings = [_w5_finding(f"c{i}", "CRITICAL") for i in range(600)]
        score = await _risk_score(findings)
        assert 95.0 <= score < 100.0

    @pytest.mark.asyncio
    async def test_info_unknown_negligible_only_scan_scores_zero(self):
        findings = [
            _w5_finding("i1", "INFO"),
            _w5_finding("u1", "UNKNOWN"),
            _w5_finding("n1", "NEGLIGIBLE"),
        ]
        assert await _risk_score(findings) == 0.0

    @pytest.mark.asyncio
    async def test_adding_a_low_finding_never_lowers_the_score(self):
        base = [_w5_finding(f"c{i}", "CRITICAL") for i in range(5)]
        before = await _risk_score(base)
        after = await _risk_score([*base, _w5_finding("l1", "LOW")])
        assert after >= before

    @pytest.mark.asyncio
    async def test_informational_noise_does_not_move_the_score(self):
        base = [_w5_finding(f"c{i}", "CRITICAL") for i in range(5)]
        noise = [_w5_finding(f"i{i}", "INFO") for i in range(200)]
        assert await _risk_score([*base, *noise]) == await _risk_score(base)

    @pytest.mark.asyncio
    async def test_monotonicity_property_over_random_finding_sets(self):
        """Adding any single finding must never decrease risk_score."""
        import random

        rng = random.Random(20260813)
        severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN", "NEGLIGIBLE"]
        for trial in range(20):
            base = [_w5_finding(f"t{trial}-f{i}", rng.choice(severities)) for i in range(rng.randint(0, 25))]
            added = _w5_finding(f"t{trial}-extra", rng.choice(severities))
            before = await _risk_score(base) if base else 0.0
            after = await _risk_score([*base, added])
            assert after >= before, f"trial {trial}: {before} -> {after} after adding {added['severity']}"

    @pytest.mark.asyncio
    async def test_many_criticals_with_noise_outrank_few_clean_criticals(self):
        """The prod inversion: 140 criticals + 225 INFO must outscore 4 criticals."""
        noisy = [_w5_finding(f"c{i}", "CRITICAL") for i in range(140)]
        noisy += [_w5_finding(f"h{i}", "HIGH") for i in range(36)]
        noisy += [_w5_finding(f"i{i}", "INFO") for i in range(225)]
        quiet = [_w5_finding(f"q{i}", "CRITICAL") for i in range(4)]
        assert await _risk_score(noisy) > await _risk_score(quiet)

    @pytest.mark.asyncio
    async def test_per_finding_enrichment_scores_do_not_change_the_base_score(self):
        """The base score depends on severity counts only, not details.risk_score."""
        plain = [_w5_finding("c1", "CRITICAL"), _w5_finding("h1", "HIGH")]
        enriched = [
            _w5_finding("c1", "CRITICAL", risk_score=95.0),
            _w5_finding("h1", "HIGH", risk_score=5.0),
        ]
        assert await _risk_score(plain) == await _risk_score(enriched)


class TestAdjustedRiskScoreReachability:
    @pytest.mark.asyncio
    async def test_no_reachability_info_adjusted_equals_base(self):
        findings = [_w5_finding("c1", "CRITICAL"), _w5_finding("h1", "HIGH")]
        db = await _seed(findings)
        stats = await calculate_comprehensive_stats(db, _W5_SCAN)
        assert stats.adjusted_risk_score == stats.risk_score

    @pytest.mark.asyncio
    async def test_all_unreachable_adjusted_below_base(self):
        findings = [_w5_finding(f"c{i}", "CRITICAL", reachable=False, reachability_level="none") for i in range(3)]
        db = await _seed(findings)
        stats = await calculate_comprehensive_stats(db, _W5_SCAN)
        assert 0.0 < stats.adjusted_risk_score < stats.risk_score

    @pytest.mark.asyncio
    async def test_confirmed_reachable_adjusted_at_least_base(self):
        findings = [_w5_finding("c1", "CRITICAL", reachable=True, reachability_level="symbol")]
        db = await _seed(findings)
        stats = await calculate_comprehensive_stats(db, _W5_SCAN)
        assert stats.risk_score <= stats.adjusted_risk_score <= 100.0


class TestPrioritizedVulnerabilityGate:
    """prioritized.* counts vulnerabilities only; other finding types must not leak in."""

    @staticmethod
    def _typed(_id, finding_type, severity="MEDIUM", details=None):
        return {
            "_id": _id,
            "finding_id": _id,
            "scan_id": _W5_SCAN,
            "type": finding_type,
            "severity": severity,
            "component": "pkg",
            "version": "1.0.0",
            "details": details or {},
            "waived": False,
        }

    @pytest.mark.asyncio
    async def test_zero_vulns_scan_has_zero_deprioritized(self):
        """Secrets/SAST/outdated findings carry no EPSS data and must not count as deprioritized vulns."""
        findings = [_secret_finding(f"s{i}", verified=False, in_current_tree=True) for i in range(3)]
        findings = [{**f, "scan_id": _W5_SCAN} for f in findings]
        findings += [self._typed(f"sast{i}", "sast", severity="HIGH") for i in range(4)]
        findings += [self._typed(f"out{i}", "outdated", severity="INFO") for i in range(10)]
        db = await _seed(findings)
        stats = await calculate_comprehensive_stats(db, _W5_SCAN)
        assert stats.prioritized.deprioritized_count == 0
        assert stats.prioritized.actionable_total == 0
        assert stats.prioritized.total == 0

    @pytest.mark.asyncio
    async def test_deprioritized_counts_only_vulnerabilities(self):
        findings = [
            self._typed("v1", "vulnerability", severity="LOW", details={"epss_score": 0.001}),
            self._typed("v2", "vulnerability", severity="MEDIUM"),  # no EPSS -> deprioritized
        ]
        findings += [self._typed(f"out{i}", "outdated", severity="INFO") for i in range(5)]
        db = await _seed(findings)
        stats = await calculate_comprehensive_stats(db, _W5_SCAN)
        assert stats.prioritized.deprioritized_count == 2

    @pytest.mark.asyncio
    async def test_prioritized_totals_and_severity_buckets_are_vuln_only(self):
        findings = [
            self._typed("v1", "vulnerability", severity="CRITICAL"),
            self._typed("q1", "quality", severity="CRITICAL"),
            self._typed("q2", "quality", severity="HIGH"),
        ]
        db = await _seed(findings)
        stats = await calculate_comprehensive_stats(db, _W5_SCAN)
        assert stats.prioritized.total == 1
        assert stats.prioritized.critical == 1
        assert stats.prioritized.high == 0
        # the all-findings severity buckets are untouched by the gate
        assert stats.critical == 2
        assert stats.high == 1

    @pytest.mark.asyncio
    async def test_actionable_counts_gated_to_vulnerabilities(self):
        findings = [
            self._typed("v1", "vulnerability", severity="CRITICAL", details={"epss_score": 0.5}),
        ]
        findings += [self._typed(f"out{i}", "outdated", severity="INFO") for i in range(3)]
        db = await _seed(findings)
        stats = await calculate_comprehensive_stats(db, _W5_SCAN)
        assert stats.prioritized.actionable_critical == 1
        assert stats.prioritized.actionable_total == 1


class TestSeverityBucketsComplete:
    """Every persisted severity lands in exactly one bucket, so buckets sum to the finding total."""

    @pytest.mark.asyncio
    async def test_negligible_bucket_counted(self):
        findings = [
            _w5_finding("c1", "CRITICAL"),
            _w5_finding("n1", "NEGLIGIBLE"),
            _w5_finding("n2", "NEGLIGIBLE"),
        ]
        db = await _seed(findings)
        stats = await calculate_comprehensive_stats(db, _W5_SCAN)
        assert stats.negligible == 2

    @pytest.mark.asyncio
    async def test_buckets_sum_to_total_finding_count(self):
        findings = [
            _w5_finding("c1", "CRITICAL"),
            _w5_finding("h1", "HIGH"),
            _w5_finding("m1", "MEDIUM"),
            _w5_finding("l1", "LOW"),
            _w5_finding("i1", "INFO"),
            _w5_finding("u1", "UNKNOWN"),
            _w5_finding("n1", "NEGLIGIBLE"),
        ]
        db = await _seed(findings)
        stats = await calculate_comprehensive_stats(db, _W5_SCAN)
        bucket_sum = (
            stats.critical + stats.high + stats.medium + stats.low + stats.info + stats.unknown + stats.negligible
        )
        assert bucket_sum == len(findings)

    @pytest.mark.asyncio
    async def test_unmapped_severity_lands_in_unknown(self):
        findings = [_w5_finding("w1", "WEIRD"), _w5_finding("u1", "UNKNOWN")]
        db = await _seed(findings)
        stats = await calculate_comprehensive_stats(db, _W5_SCAN)
        assert stats.unknown == 2


# calculate_comprehensive_stats must read KEV state from details.in_kev /
# details.kev_ransomware_use (the keys the enrichment writer persists).


def _kev_finding(_id, *, in_kev=False, kev_ransomware_use=False):
    details: dict = {}
    if in_kev:
        details["in_kev"] = True
    if kev_ransomware_use:
        details["kev_ransomware_use"] = True
    return {
        "_id": _id,
        "finding_id": _id,
        "scan_id": _W5_SCAN,
        "type": "vulnerability",
        "severity": "HIGH",
        "component": "pkg",
        "version": "1.0.0",
        "details": details,
        "waived": False,
    }


class TestComprehensiveStatsReachabilityTiers:
    """Reachability tiers derive from (reachable, analysis_level): symbol->confirmed, import->likely."""

    @pytest.mark.asyncio
    async def test_import_level_reachable_counts_as_likely(self):
        findings = [_w5_finding("i1", "HIGH", reachable=True, reachability_level="import")]
        db = await _seed(findings)
        stats = await calculate_comprehensive_stats(db, _W5_SCAN)
        assert stats.reachability.likely_reachable_count == 1

    @pytest.mark.asyncio
    async def test_symbol_level_reachable_is_not_likely(self):
        findings = [_w5_finding("s1", "HIGH", reachable=True, reachability_level="symbol")]
        db = await _seed(findings)
        stats = await calculate_comprehensive_stats(db, _W5_SCAN)
        # symbol-level is the stronger 'confirmed' tier, not 'likely'
        assert stats.reachability.likely_reachable_count == 0

    @pytest.mark.asyncio
    async def test_confirmed_vs_total_reachable_counts(self):
        """confirmed_reachable_count = symbol-level; reachable_count = total (confirmed + likely)."""
        findings = [
            _w5_finding("s1", "HIGH", reachable=True, reachability_level="symbol"),
            _w5_finding("i1", "HIGH", reachable=True, reachability_level="import"),
        ]
        db = await _seed(findings)
        stats = await calculate_comprehensive_stats(db, _W5_SCAN)
        assert stats.reachability.confirmed_reachable_count == 1
        assert stats.reachability.likely_reachable_count == 1
        assert stats.reachability.reachable_count == 2


class TestComprehensiveStatsEpssZero:
    """A legitimate EPSS of 0.0 must be reported as 0.0, not dropped to None by a truthiness guard."""

    @staticmethod
    def _epss_finding(_id, epss):
        return {
            "_id": _id,
            "finding_id": _id,
            "scan_id": _W5_SCAN,
            "type": "vulnerability",
            "severity": "HIGH",
            "component": "pkg",
            "version": "1.0.0",
            "details": {"epss_score": epss},
            "waived": False,
        }

    @pytest.mark.asyncio
    async def test_all_zero_epss_reports_zero_not_none(self):
        findings = [self._epss_finding("z1", 0.0), self._epss_finding("z2", 0.0)]
        db = await _seed(findings)
        stats = await calculate_comprehensive_stats(db, _W5_SCAN)
        assert stats.threat_intel.avg_epss_score == 0.0
        assert stats.threat_intel.max_epss_score == 0.0


class TestComprehensiveStatsUnknownReachability:
    """unknown_count must be vuln_total - reachability_analyzed, so non-vuln findings aren't counted as unknown-reachability vulns."""

    @staticmethod
    def _typed_finding(_id, finding_type, *, reachable=None, reachability_level="unknown"):
        doc = {
            "_id": _id,
            "finding_id": _id,
            "scan_id": _W5_SCAN,
            "type": finding_type,
            "severity": "HIGH",
            "component": "pkg",
            "version": "1.0.0",
            "details": {},
            "waived": False,
        }
        if reachable is not None:
            doc["reachable"] = reachable
            doc["reachability_level"] = reachability_level
        return doc

    @pytest.mark.asyncio
    async def test_non_vuln_findings_not_counted_as_unknown_reachability(self):
        findings = [self._typed_finding(f"lic{i}", "license") for i in range(5)]
        findings += [self._typed_finding(f"sast{i}", "sast") for i in range(3)]
        findings += [
            self._typed_finding("v1", "vulnerability", reachable=True, reachability_level="symbol"),
            self._typed_finding("v2", "vulnerability", reachable=False, reachability_level="none"),
        ]
        db = await _seed(findings)
        stats = await calculate_comprehensive_stats(db, _W5_SCAN)
        # both vulns analyzed -> 0 unknown
        assert stats.reachability.unknown_count == 0

    @pytest.mark.asyncio
    async def test_unknown_count_is_unanalyzed_vulns_only(self):
        findings = [self._typed_finding(f"lic{i}", "license") for i in range(10)]
        findings += [
            self._typed_finding("v1", "vulnerability", reachable=True, reachability_level="symbol"),
            self._typed_finding("v2", "vulnerability"),  # no reachable verdict -> unknown
            self._typed_finding("v3", "vulnerability"),  # no reachable verdict -> unknown
        ]
        db = await _seed(findings)
        stats = await calculate_comprehensive_stats(db, _W5_SCAN)
        assert stats.reachability.analyzed_count == 1
        assert stats.reachability.unknown_count == 2


class TestComprehensiveStatsKev:
    @pytest.mark.asyncio
    async def test_kev_count_reads_persisted_in_kev_key(self):
        findings = [
            _kev_finding("k1", in_kev=True),
            _kev_finding("k2", in_kev=True, kev_ransomware_use=True),
            _kev_finding("n1"),  # not in KEV
        ]
        db = await _seed(findings)
        stats = await calculate_comprehensive_stats(db, _W5_SCAN)
        assert stats.threat_intel.kev_count == 2
        assert stats.threat_intel.kev_ransomware_count == 1


_SECRET_SCAN = "scan-secret-priority"


def _secret_finding(_id, *, verified=None, in_current_tree=None, waived=False):
    details = {}
    if verified is not None:
        details["verified"] = verified
    if in_current_tree is not None:
        details["in_current_tree"] = in_current_tree
    return {
        "_id": _id,
        "finding_id": _id,
        "scan_id": _SECRET_SCAN,
        "type": "secret",
        "severity": "CRITICAL",
        "component": "config/aws.env",
        "version": "",
        "details": details,
        "waived": waived,
    }


class TestComprehensiveStatsSecretPriority:
    @pytest.mark.asyncio
    async def test_counts_by_verified_and_tree_status(self):
        findings = [
            _secret_finding("s1", verified=True, in_current_tree=True),
            _secret_finding("s2", verified=True, in_current_tree=False),
            _secret_finding("s3", verified=False, in_current_tree=True),
            _secret_finding("s4", verified=False, in_current_tree=False),
            _secret_finding("s5"),  # unknown/unknown
        ]
        db = await _seed(findings)
        stats = await calculate_comprehensive_stats(db, _SECRET_SCAN)
        assert stats.secret_priority is not None
        assert stats.secret_priority.total == 5
        assert stats.secret_priority.verified_count == 2
        assert stats.secret_priority.in_current_tree_count == 2
        assert stats.secret_priority.historical_only_count == 2
        assert stats.secret_priority.unknown_tree_count == 1
        assert stats.secret_priority.actionable_count == 1
        assert stats.secret_priority.deprioritized_count == 1

    @pytest.mark.asyncio
    async def test_waived_secrets_are_excluded(self):
        # All findings waived -> $match yields zero docs -> $group yields no rows,
        # so the whole stats_result gate stays empty: prioritized/threat_intel/
        # reachability/secret_priority are all None here, same as an empty scan.
        findings = [_secret_finding("s1", verified=True, in_current_tree=True, waived=True)]
        db = await _seed(findings)
        stats = await calculate_comprehensive_stats(db, _SECRET_SCAN)
        assert stats.secret_priority is None

    @pytest.mark.asyncio
    async def test_no_secrets_yields_zeroed_secret_priority(self):
        findings = [_w5_finding("v1", "CRITICAL")]
        db = await _seed(findings)
        stats = await calculate_comprehensive_stats(db, _W5_SCAN)
        assert stats.secret_priority is not None
        assert stats.secret_priority.total == 0
