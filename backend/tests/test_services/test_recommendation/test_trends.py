"""Tests for app.services.recommendation.trends."""

import pytest

from app.models.finding import Finding
from app.models.finding_record import FindingRecord
from app.schemas.recommendation import Priority, RecommendationType
from app.services.aggregation.aggregator import ResultAggregator
from app.services.analysis.engine import _prepare_finding_records
from app.services.recommendation.common import AFFECTED_COMPONENTS_SHOWN
from app.services.recommendation.trends import (
    _RECURRING_ROWS_SHOWN,
    PreviousScan,
    analyze_recurring_issues,
    analyze_regressions,
    build_cve_recurrence,
)
from app.services.recommendations import RecommendationEngine
from tests.helpers.findings import stored_vulnerability

_SEV_CRITICAL = "CRITICAL"
_SEV_HIGH = "HIGH"
_SEV_MEDIUM = "MEDIUM"
_SEV_LOW = "LOW"
_COMPONENT = "pkg"
_VERSION = "1.0.0"
_CVE_DEFAULT = "CVE-2024-001"
_LICENCE = "GPL-3.0"

_LOG4J = "org.apache.logging.log4j:log4j-core"
_LOG4SHELL = "CVE-2021-44228"
_LOG4J_FOLLOW_UP = "CVE-2021-45046"
_NETTY_HTTP = "io.netty:netty-codec-http"
_NETTY_HTTP2 = "io.netty:netty-codec-http2"
_RAPID_RESET = "CVE-2023-44487"


def _advisory(cve_id=_CVE_DEFAULT, severity=_SEV_CRITICAL, **later):
    return {"id": cve_id, "severity": severity, **later}


def _vuln(*advisories, component=_COMPONENT, version=_VERSION):
    return stored_vulnerability(component, version, list(advisories) or [_advisory()])


def _previous(*docs):
    previous = PreviousScan()
    for doc in docs:
        previous.add(doc)
    return previous


def _stored(analyzer, result, scan_id="scan-b"):
    """What the analysis engine persists for one analyzer result."""
    aggregator = ResultAggregator()
    aggregator.aggregate(analyzer, result)
    records, _ = _prepare_finding_records(aggregator.get_findings(), scan_id, "proj-1", None)
    return records


def _licences(components, *, versions=(_VERSION,), scan_id="scan-b"):
    issues = [
        {"component": c, "version": v, "license": _LICENCE, "severity": _SEV_MEDIUM}
        for c in components
        for v in versions
    ]
    return _stored("license_compliance", {"license_issues": issues}, scan_id)


def _outdated(count):
    items = [{"component": f"stale-{i}", "current_version": "1.0.0", "latest_version": "2.0.0"} for i in range(count)]
    return _stored("outdated_packages", {"outdated_dependencies": items})


class TestAnalyzeRegressionsEmpty:
    def test_empty_both_returns_empty(self):
        assert analyze_regressions([], PreviousScan()) == []

    def test_empty_current_returns_empty(self):
        assert analyze_regressions([], _previous(_vuln())) == []


class TestAnalyzeRegressionsNewCriticalVuln:
    def test_new_critical_vuln_produces_recommendation(self):
        assert len(analyze_regressions([_vuln(_advisory("CVE-2024-999"))], PreviousScan())) == 1

    def test_new_critical_vuln_type(self):
        rec = analyze_regressions([_vuln(_advisory("CVE-2024-999"))], PreviousScan())[0]
        assert rec.type == RecommendationType.REGRESSION_DETECTED

    def test_new_critical_vuln_priority_high(self):
        rec = analyze_regressions([_vuln(_advisory("CVE-2024-999"))], PreviousScan())[0]
        assert rec.priority == Priority.HIGH

    def test_new_critical_vuln_impact_critical_count(self):
        rec = analyze_regressions([_vuln(_advisory("CVE-2024-999"))], PreviousScan())[0]
        assert rec.impact["critical"] == 1

    def test_new_critical_vuln_affected_components(self):
        rec = analyze_regressions([_vuln(_advisory("CVE-2024-999"), component="lodash")], PreviousScan())[0]
        assert rec.affected_components == ["lodash"]

    def test_new_critical_vuln_action_cves(self):
        rec = analyze_regressions([_vuln(_advisory("CVE-2024-999"))], PreviousScan())[0]
        assert rec.action["new_critical_cves"] == ["CVE-2024-999"]

    def test_the_action_names_how_many_critical_cves_it_sampled(self):
        population = AFFECTED_COMPONENTS_SHOWN + 2

        rec = analyze_regressions(
            [_vuln(*(_advisory(f"CVE-2024-{i:04d}") for i in range(population)))], PreviousScan()
        )[0]

        assert len(rec.action["new_critical_cves"]) == AFFECTED_COMPONENTS_SHOWN
        assert rec.action["new_critical_cves_total"] == population


class TestAnalyzeRegressionsNewHighVuln:
    def test_new_high_vuln_priority_medium(self):
        rec = analyze_regressions([_vuln(_advisory("CVE-2024-100", _SEV_HIGH))], PreviousScan())[0]
        assert rec.priority == Priority.MEDIUM

    def test_new_high_vuln_impact_high_count(self):
        rec = analyze_regressions([_vuln(_advisory("CVE-2024-100", _SEV_HIGH))], PreviousScan())[0]
        assert rec.impact["high"] == 1
        assert rec.impact["critical"] == 0


class TestAnalyzeRegressionsDeltaThreshold:
    """More than FINDING_DELTA_THRESHOLD (10) new findings, none of them a critical/high CVE."""

    def test_delta_above_threshold_produces_one_low_priority_card(self):
        [rec] = analyze_regressions(_licences([f"lib-{i}" for i in range(12)]), PreviousScan())
        assert rec.priority == Priority.LOW
        assert rec.type == RecommendationType.REGRESSION_DETECTED

    def test_delta_exactly_at_threshold_no_recommendation(self):
        assert analyze_regressions(_licences([f"lib-{i}" for i in range(10)]), PreviousScan()) == []

    def test_delta_below_threshold_no_recommendation(self):
        assert analyze_regressions(_licences([f"lib-{i}" for i in range(5)]), PreviousScan()) == []


class TestAnalyzeRegressionsPerAdvisory:
    """A regression is an advisory the preceding scan did not report on the same artifact."""

    def test_same_findings_no_regression(self):
        finding = _vuln()
        assert analyze_regressions([finding], _previous(finding)) == []

    def test_a_record_whose_advisory_list_shrank_is_no_regression(self):
        previous = _vuln(_advisory(_LOG4SHELL), _advisory(_LOG4J_FOLLOW_UP), component=_LOG4J, version="2.14.1")
        current = _vuln(_advisory(_LOG4SHELL), component=_LOG4J, version="2.14.1")

        assert analyze_regressions([current], _previous(previous)) == []

    def test_a_low_advisory_added_to_a_critical_record_is_no_critical_regression(self):
        previous = _vuln(_advisory(_LOG4SHELL), component=_LOG4J)
        current = _vuln(_advisory(_LOG4SHELL), _advisory("CVE-2099-0001", _SEV_LOW), component=_LOG4J)

        assert analyze_regressions([current], _previous(previous)) == []

    def test_a_high_advisory_added_to_a_critical_record_counts_at_its_own_severity(self):
        previous = _vuln(_advisory(_LOG4SHELL), component=_LOG4J)
        current = _vuln(_advisory(_LOG4SHELL), _advisory(_LOG4J_FOLLOW_UP, _SEV_HIGH), component=_LOG4J)

        rec = analyze_regressions([current], _previous(previous))[0]

        assert rec.priority == Priority.MEDIUM
        assert rec.title == "Regression: 0 critical, 1 high severity vulnerabilities introduced"
        assert rec.action["new_critical_cves"] == []

    def test_an_advisory_waived_since_the_previous_scan_is_no_regression(self):
        previous = _vuln(_advisory("CVE-2024-0001"), _advisory("CVE-2024-0002"))
        current = _vuln(_advisory("CVE-2024-0001"), _advisory("CVE-2024-0002", waived=True))

        assert analyze_regressions([current], _previous(previous)) == []

    def test_an_advisory_arriving_waived_is_no_regression(self):
        previous = _vuln(_advisory("CVE-2024-0001"))
        current = _vuln(_advisory("CVE-2024-0001"), _advisory("CVE-2024-0002", waived=True))

        assert analyze_regressions([current], _previous(previous)) == []

    def test_a_version_bump_carrying_its_cves_is_no_regression(self):
        previous = _vuln(_advisory(_RAPID_RESET), component=_NETTY_HTTP, version="4.1.100")
        current = _vuln(_advisory(_RAPID_RESET), component=_NETTY_HTTP, version="4.1.101")

        assert analyze_regressions([current], _previous(previous)) == []

    def test_a_requalified_component_is_not_a_regression(self):
        """Scanners disagree on how far a package name is qualified."""
        previous = _vuln(_advisory("CVE-2020-36518"), component="com.fasterxml.jackson.core:jackson-databind")
        current = _vuln(_advisory("CVE-2020-36518"), component="jackson-databind")

        assert analyze_regressions([current], _previous(previous)) == []

    def test_a_shared_cve_on_a_newly_introduced_artifact_is_named(self):
        """One netty CVE is filed against several artifacts; the new artifact brought it in."""
        http = _vuln(_advisory(_RAPID_RESET), component=_NETTY_HTTP, version="4.1.100")
        http2 = _vuln(_advisory(_RAPID_RESET), component=_NETTY_HTTP2, version="4.1.100")

        rec = analyze_regressions([http, http2], _previous(http))[0]

        assert rec.impact["critical"] == 1
        assert rec.affected_components == [_NETTY_HTTP2]
        assert rec.action["new_critical_cves"] == [_RAPID_RESET]

    def test_a_cve_introduced_on_two_artifacts_counts_once(self):
        current = [
            _vuln(_advisory(_RAPID_RESET), component=_NETTY_HTTP, version="4.1.100"),
            _vuln(_advisory(_RAPID_RESET), component=_NETTY_HTTP2, version="4.1.100"),
        ]

        rec = analyze_regressions(current, PreviousScan())[0]

        assert rec.impact["total"] == 1
        assert rec.affected_components == [_NETTY_HTTP, _NETTY_HTTP2]

    def test_each_introduced_cve_counts_at_its_own_severity(self):
        current = _vuln(_advisory("CVE-2024-0001", _SEV_HIGH), _advisory("CVE-2024-0002", _SEV_LOW))

        rec = analyze_regressions([current], PreviousScan())[0]

        assert rec.priority == Priority.MEDIUM
        assert rec.impact == {"critical": 0, "high": 1, "medium": 0, "low": 1, "total": 2}

    def test_only_the_published_advisory_is_named_as_introduced(self):
        previous = _vuln(_advisory("CVE-2020-36518"))
        current = _vuln(_advisory("CVE-2020-36518"), _advisory("CVE-2026-11111"))

        rec = analyze_regressions([current], _previous(previous))[0]

        assert rec.impact["critical"] == 1
        assert rec.action["new_critical_cves"] == ["CVE-2026-11111"]


class TestAnalyzeRegressionsNewCount:
    """The fallback card counts security findings the previous scan did not report."""

    def test_swapped_findings_are_new_although_the_count_is_unchanged(self):
        previous = _licences([f"old-{i}" for i in range(30)], scan_id="scan-a")
        current = _licences([f"new-{i}" for i in range(30)])

        [rec] = analyze_regressions(current, _previous(*previous))

        assert rec.title == "30 new findings since the last scan"
        assert rec.impact == {"total": 0}
        assert rec.action == {"type": "review_changes", "new_findings": 30}

    def test_findings_recounted_under_one_identity_are_not_new(self):
        previous = _licences(["left-pad"], scan_id="scan-a")
        current = _licences(["left-pad"], versions=[f"1.0.{i}" for i in range(16)])

        assert analyze_regressions(current, _previous(*previous)) == []

    def test_new_outdated_findings_raise_no_card(self):
        unchanged = _vuln(_advisory(severity=_SEV_HIGH))

        assert analyze_regressions([unchanged, *_outdated(15)], _previous(unchanged)) == []

    def test_outdated_findings_replacing_a_system_warning_raise_no_card(self):
        previous = _stored("trivy", {"error": "database download timed out"}, scan_id="scan-a")

        assert analyze_regressions(_outdated(40), _previous(*previous)) == []

    def test_the_regression_card_counts_new_security_findings(self):
        current = [_vuln(_advisory("CVE-2024-999")), *_licences(["a", "b", "c"]), *_outdated(5)]

        rec = analyze_regressions(current, PreviousScan())[0]

        assert "detected 4 new findings" in rec.description


class TestAnalyzeRegressionsIdentity:
    """The pair is matched on the identity the scan delta uses."""

    def test_the_scan_scoped_document_id_does_not_enter_the_key(self):
        previous = _licences([f"lib-{i}" for i in range(12)], scan_id="scan-a")
        current = _licences([f"lib-{i}" for i in range(12)], scan_id="scan-b")

        assert analyze_regressions(current, _previous(*previous)) == []

    def test_a_stored_model_matches_its_document(self):
        """The endpoint hands the engine FindingRecord models while the previous scan streams raw documents."""
        previous = _licences([f"lib-{i}" for i in range(12)], scan_id="scan-a")
        current = [FindingRecord(**record) for record in _licences([f"lib-{i}" for i in range(12)])]

        assert analyze_regressions(current, _previous(*previous)) == []

    def test_a_stored_vulnerability_model_matches_its_document(self):
        finding = Finding.model_validate(_vuln(_advisory(_LOG4SHELL), component=_LOG4J))
        [previous], _ = _prepare_finding_records([finding], "scan-a", "proj-1", None)
        [current], _ = _prepare_finding_records([finding], "scan-b", "proj-1", None)

        assert analyze_regressions([FindingRecord(**current)], _previous(previous)) == []


_WINDOW_SCANS = 10
_OVERFLOW_FINDINGS = 600


def _scan_vuln(scan_id, cve_id=_CVE_DEFAULT, severity=_SEV_CRITICAL, component=_COMPONENT):
    """The projection ``iter_vulnerability_identities`` yields, one row per stored finding."""
    return {
        "scan_id": scan_id,
        "component": component,
        "details": {"vulnerabilities": [{"id": cve_id, "severity": severity}]},
    }


async def _recurrence(findings):
    async def _stream():
        for finding in findings:
            yield finding

    return await build_cve_recurrence(_stream())


def _across(scan_count, *, cve_id=_CVE_DEFAULT, severity=_SEV_CRITICAL, component=_COMPONENT):
    return [_scan_vuln(f"scan{i}", cve_id=cve_id, severity=severity, component=component) for i in range(scan_count)]


class TestAnalyzeRecurringIssuesEmpty:
    def test_empty_recurrence_returns_empty(self):
        assert analyze_recurring_issues({}, _WINDOW_SCANS) == []

    @pytest.mark.asyncio
    async def test_single_scan_returns_empty(self):
        assert analyze_recurring_issues(await _recurrence(_across(1)), _WINDOW_SCANS) == []


class TestAnalyzeRecurringIssuesThreshold:
    """A CVE must appear in 3+ scans to be recurring."""

    @pytest.mark.asyncio
    async def test_cve_in_two_scans_no_recommendation(self):
        assert analyze_recurring_issues(await _recurrence(_across(2)), _WINDOW_SCANS) == []

    @pytest.mark.asyncio
    async def test_cve_in_three_scans_produces_recommendation(self):
        assert len(analyze_recurring_issues(await _recurrence(_across(3)), _WINDOW_SCANS)) == 1

    @pytest.mark.asyncio
    async def test_cve_in_three_scans_type(self):
        rec = analyze_recurring_issues(await _recurrence(_across(3)), _WINDOW_SCANS)[0]
        assert rec.type == RecommendationType.RECURRING_VULNERABILITY

    @pytest.mark.asyncio
    async def test_cve_in_four_scans_still_one_recommendation(self):
        assert len(analyze_recurring_issues(await _recurrence(_across(4)), _WINDOW_SCANS)) == 1

    @pytest.mark.asyncio
    async def test_one_scan_reporting_a_cve_three_times_is_not_recurrence(self):
        """Three components carrying one CVE in a single scan is breadth, not persistence."""
        findings = [_scan_vuln("scan0", component=f"pkg-{i}") for i in range(3)]

        assert analyze_recurring_issues(await _recurrence(findings), _WINDOW_SCANS) == []


class TestAnalyzeRecurringIssuesPriority:
    """Priority depends on whether any recurring CVE is CRITICAL."""

    @pytest.mark.asyncio
    async def test_critical_recurring_gives_medium_priority(self):
        rec = analyze_recurring_issues(await _recurrence(_across(3, severity="CRITICAL")), _WINDOW_SCANS)[0]
        assert rec.priority == Priority.MEDIUM

    @pytest.mark.asyncio
    async def test_high_recurring_gives_low_priority(self):
        rec = analyze_recurring_issues(await _recurrence(_across(3, severity="HIGH")), _WINDOW_SCANS)[0]
        assert rec.priority == Priority.LOW

    @pytest.mark.asyncio
    async def test_medium_recurring_gives_low_priority(self):
        rec = analyze_recurring_issues(await _recurrence(_across(3, severity="MEDIUM")), _WINDOW_SCANS)[0]
        assert rec.priority == Priority.LOW

    @pytest.mark.asyncio
    async def test_mixed_critical_and_high_gives_medium_priority(self):
        findings = _across(3, cve_id="CVE-2024-001", severity="CRITICAL") + _across(
            3, cve_id="CVE-2024-002", severity="HIGH"
        )
        rec = analyze_recurring_issues(await _recurrence(findings), _WINDOW_SCANS)[0]
        assert rec.priority == Priority.MEDIUM


class TestAnalyzeRecurringIssuesReporting:
    @pytest.mark.asyncio
    async def test_the_action_row_names_the_components_and_scans_of_a_cve(self):
        rec = analyze_recurring_issues(await _recurrence(_across(3, component="lodash")), _WINDOW_SCANS)[0]

        assert rec.affected_components == ["lodash"]
        assert rec.action["cves"] == [{"cve": _CVE_DEFAULT, "components": ["lodash"], "scans": 3}]
        assert rec.action["cves_total"] == 1

    @pytest.mark.asyncio
    async def test_every_component_carrying_a_cve_is_affected(self):
        findings = _across(3, component="lodash") + _across(3, component="lodash-es")

        rec = analyze_recurring_issues(await _recurrence(findings), _WINDOW_SCANS)[0]

        assert rec.affected_components == ["lodash", "lodash-es"]
        assert rec.action["cves"][0]["components"] == ["lodash", "lodash-es"]

    @pytest.mark.asyncio
    async def test_many_cves_in_one_package_affect_one_component(self):
        population = _RECURRING_ROWS_SHOWN + 5
        findings = [f for i in range(population) for f in _across(3, cve_id=f"CVE-2024-{i:04d}", component="lodash")]

        rec = analyze_recurring_issues(await _recurrence(findings), _WINDOW_SCANS)[0]

        assert (rec.affected_components, rec.affected_components_total) == (["lodash"], 1)
        assert len(rec.action["cves"]) == _RECURRING_ROWS_SHOWN
        assert rec.action["cves_total"] == population

    @pytest.mark.asyncio
    async def test_the_most_persistent_recurrence_is_named_first(self):
        findings = (
            _across(5, cve_id="CVE-2024-0005", severity="CRITICAL", component="pkg-a")
            + _across(4, cve_id="CVE-2024-0004", severity="CRITICAL", component="pkg-b")
            + _across(4, cve_id="CVE-2024-0003", severity="LOW", component="pkg-c")
            + _across(3, cve_id="CVE-2024-0002", severity="CRITICAL", component="pkg-d")
        )

        rec = analyze_recurring_issues(await _recurrence(findings), _WINDOW_SCANS)[0]

        assert [row["cve"] for row in rec.action["cves"]] == [
            "CVE-2024-0005",
            "CVE-2024-0004",
            "CVE-2024-0003",
            "CVE-2024-0002",
        ]
        assert rec.affected_components == ["pkg-a", "pkg-b", "pkg-c", "pkg-d"]

    @pytest.mark.asyncio
    async def test_description_names_the_window_the_count_was_taken_over(self):
        rec = analyze_recurring_issues(await _recurrence(_across(3)), _WINDOW_SCANS)[0]
        assert f"last {_WINDOW_SCANS} scans" in rec.description


class TestBuildCveRecurrence:
    @pytest.mark.asyncio
    async def test_a_cve_past_the_500th_finding_of_a_scan_still_counts(self):
        findings = []
        for scan_index in range(3):
            scan_id = f"scan{scan_index}"
            findings += [
                _scan_vuln(scan_id, cve_id=f"CVE-2021-{i:05d}", component=f"noise-{i}")
                for i in range(_OVERFLOW_FINDINGS - 1)
            ]
            findings.append(_scan_vuln(scan_id, cve_id="CVE-2020-99999", component="libcurl"))

        recurrence = await _recurrence(findings)

        assert len(recurrence["CVE-2020-99999"].scans) == 3
        rec = analyze_recurring_issues(recurrence, _WINDOW_SCANS)[0]
        assert rec.impact["total"] == _OVERFLOW_FINDINGS

    @pytest.mark.asyncio
    async def test_an_advisory_listed_as_ghsa_and_cve_counts_once(self):
        findings = [
            {
                "scan_id": f"scan{i}",
                "component": _COMPONENT,
                "details": {"vulnerabilities": [{"id": "GHSA-aaaa", "aliases": ["CVE-2024-001"]}]},
            }
            for i in range(3)
        ]

        recurrence = await _recurrence(findings)

        assert list(recurrence) == ["CVE-2024-001"]

    @pytest.mark.asyncio
    async def test_each_cve_keeps_its_own_advisory_severity_not_its_findings(self):
        bundled = {
            "vulnerabilities": [
                {"id": "CVE-2024-0001", "severity": "CRITICAL"},
                {"id": "CVE-2024-0002", "severity": "LOW"},
            ]
        }
        rows = [{**_scan_vuln(f"scan{i}"), "details": bundled} for i in range(3)]

        recurrence = await _recurrence(rows)

        assert {cve: row.severity for cve, row in recurrence.items()} == {
            "CVE-2024-0001": "CRITICAL",
            "CVE-2024-0002": "LOW",
        }


_LODASH_CVE = "CVE-2021-23337"
_LODASH_SIBLING_CVE = "CVE-2020-8203"


def _recurring_cards(findings, recurrence):
    recs = RecommendationEngine().generate_recommendations(
        findings=findings, cve_recurrence=recurrence, recurrence_window_scans=8
    )
    return [r for r in recs if r.type == RecommendationType.RECURRING_VULNERABILITY]


class TestRecurringNamesOnlyWhatTheViewedScanStillCarries:
    @pytest.mark.asyncio
    async def test_cves_the_viewed_scan_fixed_or_waived_are_not_reported(self):
        lodash = [_scan_vuln(f"s{i}", cve_id=_LODASH_CVE, component="lodash") for i in range(1, 6)]
        minimist = [_scan_vuln(f"s{i}", cve_id="CVE-2021-44906", component="minimist") for i in range(4, 8)]

        assert _recurring_cards([], await _recurrence(lodash + minimist)) == []

    @pytest.mark.asyncio
    async def test_a_cve_waived_in_the_viewed_scan_is_left_off_while_its_live_sibling_recurs(self):
        window = [
            {
                **_scan_vuln(f"s{i}", component="lodash"),
                "details": {"vulnerabilities": [_advisory(_LODASH_CVE), _advisory(_LODASH_SIBLING_CVE)]},
            }
            for i in range(3)
        ]
        viewed = stored_vulnerability(
            "lodash", "4.17.20", [_advisory(_LODASH_CVE), _advisory(_LODASH_SIBLING_CVE, waived=True)]
        )

        [card] = _recurring_cards([viewed], await _recurrence(window))

        assert [row["cve"] for row in card.action["cves"]] == [_LODASH_CVE]
