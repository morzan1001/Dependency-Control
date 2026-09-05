"""Tests for app.services.recommendation.trends."""

import pytest

from app.schemas.recommendation import Priority, RecommendationType
from app.services.analytics.findings_delta import finding_identity_key
from app.services.recommendation.trends import (
    _identity,
    analyze_recurring_issues,
    analyze_regressions,
    build_cve_recurrence,
)

_SEV_CRITICAL = "CRITICAL"
_SEV_MEDIUM = "MEDIUM"
_COMPONENT = "pkg"
_VERSION = "1.0.0"
_CVE_DEFAULT = "CVE-2024-001"
_LICENCE_DEFAULT = "MIT"
_LICENCE_CATEGORY = "permissive"


def _vuln(severity=_SEV_CRITICAL, component=_COMPONENT, cve_id=_CVE_DEFAULT, version=_VERSION):
    """The stored shape: one aggregated record per component@version carrying an advisory list."""
    return {
        "type": "vulnerability",
        "severity": severity,
        "component": component,
        "version": version,
        "id": f"{component}:{version}",
        "finding_id": f"{component}:{version}",
        "details": {"vulnerabilities": [{"id": cve_id, "severity": severity}]},
    }


def _multi_cve_vuln(cve_ids, severity=_SEV_CRITICAL, component=_COMPONENT, version=_VERSION):
    """One record whose advisory list carries several CVEs against the same installed version."""
    record = _vuln(severity=severity, component=component, version=version)
    record["details"] = {"vulnerabilities": [{"id": cve, "severity": severity} for cve in cve_ids]}
    return record


def _non_vuln(component=_COMPONENT, licence=_LICENCE_DEFAULT):
    return {
        "type": "license",
        "severity": _SEV_MEDIUM,
        "component": component,
        "version": _VERSION,
        "id": f"LIC-{licence}",
        "finding_id": f"LIC-{licence}",
        "details": {"license": licence, "category": _LICENCE_CATEGORY},
    }


class TestAnalyzeRegressionsEmpty:
    def test_empty_both_returns_empty(self):
        assert analyze_regressions([], []) == []

    def test_empty_current_returns_empty(self):
        assert analyze_regressions([], [_vuln()]) == []


class TestAnalyzeRegressionsNewCriticalVuln:
    def test_new_critical_vuln_produces_recommendation(self):
        current = [_vuln(severity="CRITICAL", cve_id="CVE-2024-999")]
        previous = []
        result = analyze_regressions(current, previous)
        assert len(result) == 1

    def test_new_critical_vuln_type(self):
        current = [_vuln(severity="CRITICAL", cve_id="CVE-2024-999")]
        previous = []
        rec = analyze_regressions(current, previous)[0]
        assert rec.type == RecommendationType.REGRESSION_DETECTED

    def test_new_critical_vuln_priority_high(self):
        current = [_vuln(severity="CRITICAL", cve_id="CVE-2024-999")]
        previous = []
        rec = analyze_regressions(current, previous)[0]
        assert rec.priority == Priority.HIGH

    def test_new_critical_vuln_impact_critical_count(self):
        current = [_vuln(severity="CRITICAL", cve_id="CVE-2024-999")]
        previous = []
        rec = analyze_regressions(current, previous)[0]
        assert rec.impact["critical"] == 1

    def test_new_critical_vuln_affected_components(self):
        current = [_vuln(severity="CRITICAL", cve_id="CVE-2024-999", component="lodash")]
        previous = []
        rec = analyze_regressions(current, previous)[0]
        assert "lodash" in rec.affected_components

    def test_new_critical_vuln_action_cves(self):
        current = [_vuln(severity="CRITICAL", cve_id="CVE-2024-999")]
        previous = []
        rec = analyze_regressions(current, previous)[0]
        assert "CVE-2024-999" in rec.action["new_critical_cves"]


class TestAnalyzeRegressionsNewHighVuln:
    def test_new_high_vuln_produces_recommendation(self):
        current = [_vuln(severity="HIGH", cve_id="CVE-2024-100")]
        previous = []
        result = analyze_regressions(current, previous)
        assert len(result) == 1

    def test_new_high_vuln_priority_medium(self):
        current = [_vuln(severity="HIGH", cve_id="CVE-2024-100")]
        previous = []
        rec = analyze_regressions(current, previous)[0]
        assert rec.priority == Priority.MEDIUM

    def test_new_high_vuln_impact_high_count(self):
        current = [_vuln(severity="HIGH", cve_id="CVE-2024-100")]
        previous = []
        rec = analyze_regressions(current, previous)[0]
        assert rec.impact["high"] == 1
        assert rec.impact["critical"] == 0


class TestAnalyzeRegressionsDeltaThreshold:
    """Finding delta > FINDING_DELTA_THRESHOLD (10) but no critical/high."""

    def test_delta_above_threshold_produces_low_priority(self):
        # 12 new non-vuln findings, 0 previous => delta = 12 > 10
        current = [_non_vuln(licence=f"LIC-{i}") for i in range(12)]
        previous = []
        result = analyze_regressions(current, previous)
        assert len(result) == 1

    def test_delta_above_threshold_priority_low(self):
        current = [_non_vuln(licence=f"LIC-{i}") for i in range(12)]
        previous = []
        rec = analyze_regressions(current, previous)[0]
        assert rec.priority == Priority.LOW

    def test_delta_above_threshold_type(self):
        current = [_non_vuln(licence=f"LIC-{i}") for i in range(12)]
        previous = []
        rec = analyze_regressions(current, previous)[0]
        assert rec.type == RecommendationType.REGRESSION_DETECTED

    def test_delta_exactly_at_threshold_no_recommendation(self):
        # delta = 10, threshold is > 10, so no recommendation
        current = [_non_vuln(licence=f"LIC-{i}") for i in range(10)]
        previous = []
        result = analyze_regressions(current, previous)
        assert len(result) == 0

    def test_delta_below_threshold_no_recommendation(self):
        current = [_non_vuln(licence=f"LIC-{i}") for i in range(5)]
        previous = []
        result = analyze_regressions(current, previous)
        assert len(result) == 0


class TestAnalyzeRegressionsSameFindings:
    def test_same_findings_no_regression(self):
        finding = _vuln(severity="CRITICAL", cve_id="CVE-2024-001")
        result = analyze_regressions([finding], [finding])
        assert len(result) == 0

    def test_fewer_findings_no_regression(self):
        previous = [_vuln(cve_id="CVE-2024-001"), _vuln(cve_id="CVE-2024-002")]
        current = [_vuln(cve_id="CVE-2024-001")]
        result = analyze_regressions(current, previous)
        assert len(result) == 0


class TestAnalyzeRegressionsMixedNewFindings:
    def test_both_critical_and_high_priority_is_high(self):
        current = [
            _vuln(severity="CRITICAL", cve_id="CVE-2024-100"),
            _vuln(severity="HIGH", cve_id="CVE-2024-200"),
        ]
        previous = []
        rec = analyze_regressions(current, previous)[0]
        assert rec.priority == Priority.HIGH

    def test_title_includes_counts(self):
        current = [
            _vuln(severity="CRITICAL", cve_id="CVE-2024-100"),
            _vuln(severity="HIGH", cve_id="CVE-2024-200"),
            _vuln(severity="HIGH", cve_id="CVE-2024-201"),
        ]
        previous = []
        rec = analyze_regressions(current, previous)[0]
        assert "1 critical" in rec.title
        assert "2 high" in rec.title


_BARE_COMPONENT = "jackson-databind"
_QUALIFIED_COMPONENT = "com.fasterxml.jackson.core:jackson-databind"
_CARRIED_CVE = "CVE-2020-36518"
_PUBLISHED_CVE = "CVE-2026-11111"
_SCAN_A_DOCUMENT_ID = "scan-a:pkg:1.0.0"
_SCAN_B_DOCUMENT_ID = "scan-b:pkg:1.0.0"


class TestAnalyzeRegressionsIdentity:
    """The pair is matched on the identity the scan delta uses, so the two never disagree about
    whether a finding is the same one."""

    def test_the_scan_scoped_document_id_does_not_enter_the_key(self):
        previous = _vuln() | {"_id": _SCAN_A_DOCUMENT_ID}
        current = _vuln() | {"_id": _SCAN_B_DOCUMENT_ID}

        assert analyze_regressions([current], [previous]) == []

    def test_a_requalified_component_is_not_a_regression(self):
        """Scanners disagree on how far a package name is qualified; the delta folds both to the
        artefact name, so a requalified record must not read as introduced."""
        previous = _vuln(component=_QUALIFIED_COMPONENT, cve_id=_CARRIED_CVE)
        current = _vuln(component=_BARE_COMPONENT, cve_id=_CARRIED_CVE)

        assert analyze_regressions([current], [previous]) == []

    def test_an_advisory_published_against_the_installed_version_is_a_regression(self):
        previous = [_vuln(cve_id=_CARRIED_CVE)]
        current = [_multi_cve_vuln([_CARRIED_CVE, _PUBLISHED_CVE])]

        rec = analyze_regressions(current, previous)[0]

        assert rec.impact["critical"] == 1

    def test_only_the_published_advisory_is_named_as_introduced(self):
        previous = [_vuln(cve_id=_CARRIED_CVE)]
        current = [_multi_cve_vuln([_CARRIED_CVE, _PUBLISHED_CVE])]

        rec = analyze_regressions(current, previous)[0]

        assert rec.action["new_critical_cves"] == [_PUBLISHED_CVE]

    @pytest.mark.parametrize("record", [_vuln(), _multi_cve_vuln([_CARRIED_CVE, _PUBLISHED_CVE]), _non_vuln()])
    def test_the_projection_carries_everything_the_delta_key_reads(self, record):
        """A field missing from the projection silently degrades the key to the description hash."""
        assert _identity(record) == finding_identity_key(record)

    def test_the_stored_document_and_its_model_key_alike(self):
        """The endpoint hands the engine FindingRecord models while the delta reads raw documents."""
        from app.models.finding import Finding
        from app.models.finding_record import FindingRecord
        from app.services.analysis.engine import _prepare_finding_records

        aggregated = Finding(
            id=f"{_BARE_COMPONENT}:{_VERSION}",
            type="vulnerability",
            severity=_SEV_CRITICAL,
            component=_BARE_COMPONENT,
            version=_VERSION,
            description="",
            scanners=["osv"],
            details={"vulnerabilities": [{"id": _CARRIED_CVE, "severity": _SEV_CRITICAL}]},
        )
        (record,), _ = _prepare_finding_records([aggregated], _SCAN_A_DOCUMENT_ID, "proj-1", None)

        assert _identity(FindingRecord(**record)) == finding_identity_key(record)


_WINDOW_SCANS = 10
# More vulnerability findings than one scan document's findings_summary can carry.
_SUMMARY_LIMIT = 500
_OVERFLOW_FINDINGS = 600


def _scan_vuln(scan_id, cve_id=_CVE_DEFAULT, severity=_SEV_CRITICAL, component=_COMPONENT):
    """The projection ``iter_vulnerability_identities`` yields, one row per stored finding."""
    return {
        "scan_id": scan_id,
        "severity": severity,
        "component": component,
        "finding_id": f"{component}:{_VERSION}",
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
    async def test_affected_components_format(self):
        rec = analyze_recurring_issues(await _recurrence(_across(3, component="lodash")), _WINDOW_SCANS)[0]
        assert any("CVE-2024-001" in entry and "lodash" in entry for entry in rec.affected_components)

    @pytest.mark.asyncio
    async def test_affected_components_include_scan_count(self):
        rec = analyze_recurring_issues(await _recurrence(_across(3)), _WINDOW_SCANS)[0]
        assert any("3 scans" in entry for entry in rec.affected_components)

    @pytest.mark.asyncio
    async def test_description_names_the_window_the_count_was_taken_over(self):
        rec = analyze_recurring_issues(await _recurrence(_across(3)), _WINDOW_SCANS)[0]
        assert f"last {_WINDOW_SCANS} scans" in rec.description


class TestBuildCveRecurrence:
    @pytest.mark.asyncio
    async def test_a_cve_past_the_summary_limit_still_counts(self):
        """The scan document keeps 500 findings; the recurrence read must not stop there."""
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
        # The headline counts every recurring CVE, not the summary's first 500 of them.
        assert rec.impact["total"] == _OVERFLOW_FINDINGS

    @pytest.mark.asyncio
    async def test_an_advisory_listed_as_ghsa_and_cve_counts_once(self):
        findings = [
            {
                "scan_id": f"scan{i}",
                "severity": _SEV_CRITICAL,
                "component": _COMPONENT,
                "details": {"vulnerabilities": [{"id": "GHSA-aaaa", "aliases": ["CVE-2024-001"]}]},
            }
            for i in range(3)
        ]

        recurrence = await _recurrence(findings)

        assert list(recurrence) == ["CVE-2024-001"]

    @pytest.mark.asyncio
    async def test_a_finding_naming_no_advisory_falls_back_to_its_own_identifier(self):
        findings = [
            {"scan_id": f"scan{i}", "severity": _SEV_CRITICAL, "component": _COMPONENT, "finding_id": "pkg:1.0.0"}
            for i in range(3)
        ]

        assert list(await _recurrence(findings)) == ["pkg:1.0.0"]


class TestPersistedFindingsSummary:
    """The scan document's summary is bounded to keep the scan under Mongo's document limit."""

    @staticmethod
    def _aggregated_vuln(cve_id, severity=_SEV_CRITICAL, component=_COMPONENT):
        from app.models.finding import Finding

        return Finding(
            id=cve_id,
            type="vulnerability",
            severity=severity,
            component=component,
            version=_VERSION,
            description=f"Description for {cve_id}",
            scanners=["osv"],
            details={"vulnerabilities": [{"id": cve_id, "severity": severity}], "bulky": "x" * 5000},
        )

    def test_summary_is_bounded_and_compact(self):
        from app.services.analysis.engine import (
            _build_findings_summary,
            _prepare_finding_records,
        )

        findings = [self._aggregated_vuln(f"CVE-2024-{i:04d}") for i in range(_OVERFLOW_FINDINGS)]
        _, vulnerability_findings = _prepare_finding_records(findings, "scanX", "proj-1", None)
        summary = _build_findings_summary(vulnerability_findings)

        assert len(summary) == _SUMMARY_LIMIT
        # Compact: bulky detail keys are dropped, only cve_id retained.
        assert summary[0]["details"] == {"cve_id": summary[0]["id"]}

    def test_summary_only_contains_vulnerabilities(self):
        from app.models.finding import Finding
        from app.services.analysis.engine import (
            _build_findings_summary,
            _prepare_finding_records,
        )

        license_finding = Finding(
            id="lic-1",
            type="license",
            severity=_SEV_MEDIUM,
            component=_COMPONENT,
            description="GPL",
            scanners=["licensecheck"],
        )
        vuln = self._aggregated_vuln(_CVE_DEFAULT)
        _findings_to_insert, vulnerability_findings = _prepare_finding_records(
            [license_finding, vuln], "scanY", "proj-1", None
        )
        summary = _build_findings_summary(vulnerability_findings)

        assert len(summary) == 1
        assert summary[0]["type"] == "vulnerability"
