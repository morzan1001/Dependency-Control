"""Tests for analysis stats helper functions."""

from datetime import datetime, timezone

from app.services.analysis.stats import (
    _format_datetime,
    build_epss_kev_summary,
    build_reachability_summary,
)


# ---------------------------------------------------------------------------
# _format_datetime
# ---------------------------------------------------------------------------


class TestFormatDatetime:
    """Tests for _format_datetime - safely converts values to ISO strings."""

    def test_none_returns_none(self):
        """None input produces None output."""
        assert _format_datetime(None) is None

    def test_datetime_returns_isoformat(self):
        """A datetime object is converted via isoformat()."""
        dt = datetime(2024, 6, 15, 12, 30, 0, tzinfo=timezone.utc)
        result = _format_datetime(dt)
        assert result == dt.isoformat()

    def test_string_passthrough(self):
        """A non-empty string is returned as-is."""
        assert _format_datetime("2024-01-01T00:00:00Z") == "2024-01-01T00:00:00Z"

    def test_empty_string_returns_none(self):
        """An empty string is treated as missing and returns None."""
        assert _format_datetime("") is None

    def test_int_returns_str(self):
        """An integer is coerced to its string representation."""
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
    """Create a minimal FindingDict for EPSS/KEV tests."""
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
    """Tests for build_epss_kev_summary with empty input."""

    def test_empty_list_returns_zero_totals(self):
        """An empty findings list should produce zeroed-out summary."""
        result = build_epss_kev_summary([])
        assert result["total_vulnerabilities"] == 0
        assert result["epss_enriched"] == 0
        assert result["kev_matches"] == 0
        assert result["kev_ransomware"] == 0

    def test_empty_list_scores_are_none(self):
        """No findings means no averages or maximums."""
        result = build_epss_kev_summary([])
        assert result["avg_epss_score"] is None
        assert result["max_epss_score"] is None
        assert result["avg_risk_score"] is None
        assert result["max_risk_score"] is None

    def test_empty_list_has_timestamp(self):
        """Even an empty summary should contain a UTC timestamp."""
        result = build_epss_kev_summary([])
        assert result["timestamp"] is not None


class TestBuildEpssKevSummaryEpss:
    """Tests for EPSS score handling in build_epss_kev_summary."""

    def test_single_finding_with_epss(self):
        """A single enriched finding increments epss_enriched."""
        findings = [_make_finding(epss_score=0.05)]
        result = build_epss_kev_summary(findings)
        assert result["epss_enriched"] == 1
        assert result["total_vulnerabilities"] == 1

    def test_epss_high_bucket(self):
        """Scores above 0.1 land in the high bucket."""
        findings = [_make_finding(epss_score=0.5)]
        result = build_epss_kev_summary(findings)
        assert result["epss_scores"]["high"] == 1
        assert result["epss_scores"]["medium"] == 0
        assert result["epss_scores"]["low"] == 0

    def test_epss_medium_bucket(self):
        """Scores between 0.01 and 0.1 land in the medium bucket."""
        findings = [_make_finding(epss_score=0.05)]
        result = build_epss_kev_summary(findings)
        assert result["epss_scores"]["medium"] == 1

    def test_epss_low_bucket(self):
        """Scores at or below 0.01 land in the low bucket."""
        findings = [_make_finding(epss_score=0.001)]
        result = build_epss_kev_summary(findings)
        assert result["epss_scores"]["low"] == 1

    def test_epss_boundary_high(self):
        """Score of exactly 0.1 is NOT high (strictly greater than)."""
        findings = [_make_finding(epss_score=0.1)]
        result = build_epss_kev_summary(findings)
        assert result["epss_scores"]["high"] == 0
        assert result["epss_scores"]["medium"] == 1

    def test_epss_boundary_medium(self):
        """Score of exactly 0.01 is NOT medium (strictly greater than)."""
        findings = [_make_finding(epss_score=0.01)]
        result = build_epss_kev_summary(findings)
        assert result["epss_scores"]["medium"] == 0
        assert result["epss_scores"]["low"] == 1

    def test_avg_epss_score(self):
        """Average EPSS is computed across enriched findings only."""
        findings = [
            _make_finding(finding_id="CVE-1", epss_score=0.2),
            _make_finding(finding_id="CVE-2", epss_score=0.4),
        ]
        result = build_epss_kev_summary(findings)
        assert result["avg_epss_score"] == round((0.2 + 0.4) / 2, 4)

    def test_max_epss_score(self):
        """Max EPSS is the highest enriched score."""
        findings = [
            _make_finding(finding_id="CVE-1", epss_score=0.1),
            _make_finding(finding_id="CVE-2", epss_score=0.9),
        ]
        result = build_epss_kev_summary(findings)
        assert result["max_epss_score"] == 0.9

    def test_finding_without_epss_not_counted(self):
        """Findings lacking an EPSS score should not affect EPSS stats."""
        findings = [_make_finding(epss_score=None)]
        result = build_epss_kev_summary(findings)
        assert result["epss_enriched"] == 0
        assert result["avg_epss_score"] is None


class TestBuildEpssKevSummaryKev:
    """Tests for KEV handling in build_epss_kev_summary."""

    def test_kev_match_counted(self):
        """A finding in the KEV catalog increments kev_matches."""
        findings = [_make_finding(in_kev=True)]
        result = build_epss_kev_summary(findings)
        assert result["kev_matches"] == 1

    def test_kev_detail_recorded(self):
        """KEV details include the CVE ID and component."""
        findings = [_make_finding(finding_id="CVE-2024-9999", component="openssl", in_kev=True)]
        result = build_epss_kev_summary(findings)
        assert len(result["kev_details"]) == 1
        detail = result["kev_details"][0]
        assert detail["cve"] == "CVE-2024-9999"
        assert detail["component"] == "openssl"

    def test_kev_due_date_propagated(self):
        """KEV due date is passed through to the detail entry."""
        findings = [_make_finding(in_kev=True, kev_due_date="2024-12-01")]
        result = build_epss_kev_summary(findings)
        assert result["kev_details"][0]["due_date"] == "2024-12-01"

    def test_kev_ransomware_counted(self):
        """Ransomware-related KEV entries increment kev_ransomware."""
        findings = [_make_finding(in_kev=True, kev_ransomware_use=True)]
        result = build_epss_kev_summary(findings)
        assert result["kev_ransomware"] == 1
        assert result["kev_details"][0]["ransomware"] is True

    def test_kev_no_ransomware(self):
        """Non-ransomware KEV entries leave kev_ransomware at zero."""
        findings = [_make_finding(in_kev=True, kev_ransomware_use=False)]
        result = build_epss_kev_summary(findings)
        assert result["kev_ransomware"] == 0


class TestBuildEpssKevSummaryRisk:
    """Tests for risk score and high-risk CVE handling."""

    def test_risk_score_average(self):
        """Average risk score is computed across all findings with a score."""
        findings = [
            _make_finding(finding_id="CVE-1", risk_score=80.0),
            _make_finding(finding_id="CVE-2", risk_score=60.0),
        ]
        result = build_epss_kev_summary(findings)
        assert result["avg_risk_score"] == round((80.0 + 60.0) / 2, 1)

    def test_risk_score_max(self):
        """Max risk score is the highest observed."""
        findings = [
            _make_finding(finding_id="CVE-1", risk_score=30.0),
            _make_finding(finding_id="CVE-2", risk_score=95.0),
        ]
        result = build_epss_kev_summary(findings)
        assert result["max_risk_score"] == 95.0

    def test_high_risk_cve_above_threshold(self):
        """Findings with risk_score > 70 appear in high_risk_cves."""
        findings = [_make_finding(risk_score=80.0, component="openssl", version="3.0.0")]
        result = build_epss_kev_summary(findings)
        assert len(result["high_risk_cves"]) == 1
        cve = result["high_risk_cves"][0]
        assert cve["risk_score"] == 80.0
        assert cve["component"] == "openssl"
        assert cve["version"] == "3.0.0"

    def test_high_risk_cve_at_threshold_excluded(self):
        """A risk_score of exactly 70.0 does NOT qualify (strictly greater)."""
        findings = [_make_finding(risk_score=70.0)]
        result = build_epss_kev_summary(findings)
        assert len(result["high_risk_cves"]) == 0

    def test_high_risk_cves_sorted_descending(self):
        """High-risk CVEs are sorted by risk_score descending."""
        findings = [
            _make_finding(finding_id="CVE-1", risk_score=75.0),
            _make_finding(finding_id="CVE-2", risk_score=95.0),
            _make_finding(finding_id="CVE-3", risk_score=85.0),
        ]
        result = build_epss_kev_summary(findings)
        scores = [c["risk_score"] for c in result["high_risk_cves"]]
        assert scores == sorted(scores, reverse=True)

    def test_high_risk_cves_limited_to_20(self):
        """No more than 20 high-risk CVEs are returned."""
        findings = [
            _make_finding(finding_id=f"CVE-{i}", risk_score=71.0 + i)
            for i in range(25)
        ]
        result = build_epss_kev_summary(findings)
        assert len(result["high_risk_cves"]) == 20

    def test_no_risk_scores_gives_none(self):
        """When no findings carry a risk_score, averages stay None."""
        findings = [_make_finding(risk_score=None)]
        result = build_epss_kev_summary(findings)
        assert result["avg_risk_score"] is None
        assert result["max_risk_score"] is None


class TestBuildEpssKevSummaryExploitMaturity:
    """Tests for exploit maturity counting."""

    def test_known_maturity_counted(self):
        """Recognised maturity values increment the correct bucket."""
        findings = [_make_finding(exploit_maturity="weaponized")]
        result = build_epss_kev_summary(findings)
        assert result["exploit_maturity"]["weaponized"] == 1

    def test_unknown_maturity_default(self):
        """Missing maturity defaults to 'unknown'."""
        findings = [{"details": {}, "component": "pkg"}]
        result = build_epss_kev_summary(findings)
        assert result["exploit_maturity"]["unknown"] == 1

    def test_unrecognised_maturity_ignored(self):
        """A maturity value not in the dict is silently ignored."""
        findings = [_make_finding(exploit_maturity="invented_level")]
        result = build_epss_kev_summary(findings)
        total = sum(result["exploit_maturity"].values())
        assert total == 0


class TestBuildEpssKevSummaryFindingId:
    """Tests for CVE ID extraction from findings."""

    def test_finding_id_preferred_over_id(self):
        """finding_id takes precedence when both keys exist."""
        finding = _make_finding(finding_id="CVE-PREFERRED", risk_score=80.0)
        finding["id"] = "CVE-FALLBACK"
        result = build_epss_kev_summary([finding])
        assert result["high_risk_cves"][0]["cve"] == "CVE-PREFERRED"

    def test_id_used_as_fallback(self):
        """When finding_id is absent, id is used."""
        finding = {"id": "CVE-FALLBACK", "component": "pkg", "version": "1.0", "details": {"risk_score": 80.0, "exploit_maturity": "unknown"}}
        result = build_epss_kev_summary([finding])
        assert result["high_risk_cves"][0]["cve"] == "CVE-FALLBACK"


# ---------------------------------------------------------------------------
# build_reachability_summary  –  helpers
# ---------------------------------------------------------------------------


def _make_reachable_finding(
    finding_id="CVE-2024-0001",
    component="pkg",
    version="1.0.0",
    severity="HIGH",
    reachable=None,
    reachability_level="unknown",
    reachable_functions=None,
):
    """Create a minimal FindingDict for reachability tests."""
    finding = {
        "finding_id": finding_id,
        "component": component,
        "version": version,
        "severity": severity,
        "reachability_level": reachability_level,
    }
    if reachable is not None:
        finding["reachable"] = reachable
    if reachable_functions is not None:
        finding["reachable_functions"] = reachable_functions
    return finding


def _make_callgraph(language="python", modules=None, imports=None, created_at=None):
    """Create a minimal callgraph dict."""
    cg = {"language": language}
    if modules is not None:
        cg["module_usage"] = modules
    else:
        cg["module_usage"] = {}
    if imports is not None:
        cg["import_map"] = imports
    else:
        cg["import_map"] = {}
    if created_at is not None:
        cg["created_at"] = created_at
    return cg


# ---------------------------------------------------------------------------
# build_reachability_summary
# ---------------------------------------------------------------------------


class TestBuildReachabilitySummaryEmpty:
    """Tests for build_reachability_summary with empty input."""

    def test_empty_findings(self):
        """Empty findings list produces zeroed totals."""
        result = build_reachability_summary([], _make_callgraph(), 0)
        assert result["total_vulnerabilities"] == 0
        assert result["analyzed"] == 0
        assert result["reachable_vulnerabilities"] == []
        assert result["unreachable_vulnerabilities"] == []

    def test_empty_findings_has_timestamp(self):
        """Even an empty summary contains a UTC timestamp."""
        result = build_reachability_summary([], _make_callgraph(), 0)
        assert result["timestamp"] is not None


class TestBuildReachabilitySummaryLevels:
    """Tests for reachability level counting."""

    def test_confirmed_level(self):
        """Confirmed reachability level is counted."""
        findings = [_make_reachable_finding(reachable=True, reachability_level="confirmed")]
        result = build_reachability_summary(findings, _make_callgraph(), 1)
        assert result["reachability_levels"]["confirmed"] == 1

    def test_likely_level(self):
        """Likely reachability level is counted."""
        findings = [_make_reachable_finding(reachable=True, reachability_level="likely")]
        result = build_reachability_summary(findings, _make_callgraph(), 1)
        assert result["reachability_levels"]["likely"] == 1

    def test_unknown_level(self):
        """Unknown reachability level is counted."""
        findings = [_make_reachable_finding(reachability_level="unknown")]
        result = build_reachability_summary(findings, _make_callgraph(), 0)
        assert result["reachability_levels"]["unknown"] == 1

    def test_unreachable_level(self):
        """Unreachable reachability level is counted."""
        findings = [_make_reachable_finding(reachable=False, reachability_level="unreachable")]
        result = build_reachability_summary(findings, _make_callgraph(), 1)
        assert result["reachability_levels"]["unreachable"] == 1

    def test_multiple_levels_counted(self):
        """Mixed reachability levels are counted independently."""
        findings = [
            _make_reachable_finding(finding_id="CVE-1", reachable=True, reachability_level="confirmed"),
            _make_reachable_finding(finding_id="CVE-2", reachable=True, reachability_level="likely"),
            _make_reachable_finding(finding_id="CVE-3", reachable=False, reachability_level="unreachable"),
            _make_reachable_finding(finding_id="CVE-4", reachability_level="unknown"),
        ]
        result = build_reachability_summary(findings, _make_callgraph(), 3)
        levels = result["reachability_levels"]
        assert levels["confirmed"] == 1
        assert levels["likely"] == 1
        assert levels["unreachable"] == 1
        assert levels["unknown"] == 1


class TestBuildReachabilitySummaryCallgraph:
    """Tests for callgraph_info extraction."""

    def test_language_extracted(self):
        """Callgraph language is propagated to the summary."""
        cg = _make_callgraph(language="java")
        result = build_reachability_summary([], cg, 0)
        assert result["callgraph_info"]["language"] == "java"

    def test_module_count(self):
        """Total modules equals the size of module_usage."""
        cg = _make_callgraph(modules={"mod_a": {}, "mod_b": {}})
        result = build_reachability_summary([], cg, 0)
        assert result["callgraph_info"]["total_modules"] == 2

    def test_import_count(self):
        """Total imports equals the size of import_map."""
        cg = _make_callgraph(imports={"imp_a": [], "imp_b": [], "imp_c": []})
        result = build_reachability_summary([], cg, 0)
        assert result["callgraph_info"]["total_imports"] == 3

    def test_generated_at_from_datetime(self):
        """A datetime created_at is formatted via _format_datetime."""
        dt = datetime(2024, 1, 15, 8, 0, 0, tzinfo=timezone.utc)
        cg = _make_callgraph(created_at=dt)
        result = build_reachability_summary([], cg, 0)
        assert result["callgraph_info"]["generated_at"] == dt.isoformat()

    def test_generated_at_none_when_missing(self):
        """Missing created_at yields None for generated_at."""
        cg = _make_callgraph()
        result = build_reachability_summary([], cg, 0)
        assert result["callgraph_info"]["generated_at"] is None

    def test_missing_language_defaults_to_unknown(self):
        """A callgraph without a language key defaults to 'unknown'."""
        result = build_reachability_summary([], {"module_usage": {}, "import_map": {}}, 0)
        assert result["callgraph_info"]["language"] == "unknown"


class TestBuildReachabilitySummaryPartitioning:
    """Tests for reachable vs unreachable separation."""

    def test_reachable_true_goes_to_reachable_list(self):
        """Findings with reachable=True appear in reachable_vulnerabilities."""
        findings = [_make_reachable_finding(reachable=True, reachability_level="confirmed")]
        result = build_reachability_summary(findings, _make_callgraph(), 1)
        assert len(result["reachable_vulnerabilities"]) == 1
        assert len(result["unreachable_vulnerabilities"]) == 0

    def test_reachable_false_goes_to_unreachable_list(self):
        """Findings with reachable=False appear in unreachable_vulnerabilities."""
        findings = [_make_reachable_finding(reachable=False, reachability_level="unreachable")]
        result = build_reachability_summary(findings, _make_callgraph(), 1)
        assert len(result["reachable_vulnerabilities"]) == 0
        assert len(result["unreachable_vulnerabilities"]) == 1

    def test_reachable_none_goes_to_neither_list(self):
        """Findings without a reachable value appear in neither list."""
        findings = [_make_reachable_finding(reachability_level="unknown")]
        result = build_reachability_summary(findings, _make_callgraph(), 0)
        assert len(result["reachable_vulnerabilities"]) == 0
        assert len(result["unreachable_vulnerabilities"]) == 0

    def test_vuln_info_fields(self):
        """Vulnerability info entries contain all expected fields."""
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
        result = build_reachability_summary(findings, _make_callgraph(), 1)
        vuln = result["reachable_vulnerabilities"][0]
        assert vuln["cve"] == "CVE-2024-5678"
        assert vuln["component"] == "openssl"
        assert vuln["version"] == "3.0.0"
        assert vuln["severity"] == "CRITICAL"
        assert vuln["reachability_level"] == "confirmed"
        assert vuln["reachable_functions"] == ["SSL_read"]

    def test_reachable_functions_limited_to_5(self):
        """Only the first 5 reachable functions are kept per finding."""
        funcs = [f"func_{i}" for i in range(10)]
        findings = [_make_reachable_finding(reachable=True, reachability_level="confirmed", reachable_functions=funcs)]
        result = build_reachability_summary(findings, _make_callgraph(), 1)
        assert len(result["reachable_vulnerabilities"][0]["reachable_functions"]) == 5


class TestBuildReachabilitySummarySorting:
    """Tests for severity sorting of reachable/unreachable lists."""

    def test_reachable_sorted_by_severity_descending(self):
        """Reachable vulnerabilities are sorted most-severe first."""
        findings = [
            _make_reachable_finding(finding_id="CVE-1", severity="LOW", reachable=True, reachability_level="confirmed"),
            _make_reachable_finding(finding_id="CVE-2", severity="CRITICAL", reachable=True, reachability_level="confirmed"),
            _make_reachable_finding(finding_id="CVE-3", severity="MEDIUM", reachable=True, reachability_level="likely"),
        ]
        result = build_reachability_summary(findings, _make_callgraph(), 3)
        severities = [v["severity"] for v in result["reachable_vulnerabilities"]]
        assert severities == ["CRITICAL", "MEDIUM", "LOW"]

    def test_unreachable_sorted_by_severity_descending(self):
        """Unreachable vulnerabilities are sorted most-severe first."""
        findings = [
            _make_reachable_finding(finding_id="CVE-1", severity="LOW", reachable=False, reachability_level="unreachable"),
            _make_reachable_finding(finding_id="CVE-2", severity="HIGH", reachable=False, reachability_level="unreachable"),
        ]
        result = build_reachability_summary(findings, _make_callgraph(), 2)
        severities = [v["severity"] for v in result["unreachable_vulnerabilities"]]
        assert severities == ["HIGH", "LOW"]


class TestBuildReachabilitySummaryLimits:
    """Tests for list size limits."""

    def test_reachable_limited_to_30(self):
        """No more than 30 reachable vulnerabilities are returned."""
        findings = [
            _make_reachable_finding(
                finding_id=f"CVE-{i}",
                reachable=True,
                reachability_level="confirmed",
            )
            for i in range(35)
        ]
        result = build_reachability_summary(findings, _make_callgraph(), 35)
        assert len(result["reachable_vulnerabilities"]) == 30

    def test_unreachable_limited_to_30(self):
        """No more than 30 unreachable vulnerabilities are returned."""
        findings = [
            _make_reachable_finding(
                finding_id=f"CVE-{i}",
                reachable=False,
                reachability_level="unreachable",
            )
            for i in range(35)
        ]
        result = build_reachability_summary(findings, _make_callgraph(), 35)
        assert len(result["unreachable_vulnerabilities"]) == 30

    def test_analyzed_count_passthrough(self):
        """The enriched_count argument is passed through as analyzed."""
        result = build_reachability_summary([], _make_callgraph(), 42)
        assert result["analyzed"] == 42
