"""Tests for app.services.recommendation.trends."""

import pytest

from app.schemas.recommendation import Priority, RecommendationType
from app.services.analytics.findings_delta import finding_identity_key
from app.services.recommendation.trends import (
    _identity,
    analyze_recurring_issues,
    analyze_regressions,
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


def _scan(scan_id, findings):
    return {
        "_id": scan_id,
        "findings_summary": findings,
    }


def _scan_finding(cve_id="CVE-2024-001", severity="CRITICAL", component="pkg"):
    return {
        "type": "vulnerability",
        "severity": severity,
        "component": component,
        "id": cve_id,
        "details": {"cve_id": cve_id},
        "description": f"Description for {cve_id}",
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


class TestAnalyzeRecurringIssuesEmpty:
    def test_empty_history_returns_empty(self):
        assert analyze_recurring_issues([]) == []

    def test_single_scan_returns_empty(self):
        history = [_scan("scan1", [_scan_finding()])]
        result = analyze_recurring_issues(history)
        assert len(result) == 0


class TestAnalyzeRecurringIssuesThreshold:
    """CVE must appear in 3+ scans to be recurring."""

    def test_cve_in_two_scans_no_recommendation(self):
        history = [
            _scan("scan1", [_scan_finding(cve_id="CVE-2024-001")]),
            _scan("scan2", [_scan_finding(cve_id="CVE-2024-001")]),
        ]
        result = analyze_recurring_issues(history)
        assert len(result) == 0

    def test_cve_in_three_scans_produces_recommendation(self):
        history = [
            _scan("scan1", [_scan_finding(cve_id="CVE-2024-001")]),
            _scan("scan2", [_scan_finding(cve_id="CVE-2024-001")]),
            _scan("scan3", [_scan_finding(cve_id="CVE-2024-001")]),
        ]
        result = analyze_recurring_issues(history)
        assert len(result) == 1

    def test_cve_in_three_scans_type(self):
        history = [_scan(f"scan{i}", [_scan_finding(cve_id="CVE-2024-001")]) for i in range(3)]
        rec = analyze_recurring_issues(history)[0]
        assert rec.type == RecommendationType.RECURRING_VULNERABILITY

    def test_cve_in_four_scans_still_one_recommendation(self):
        history = [_scan(f"scan{i}", [_scan_finding(cve_id="CVE-2024-001")]) for i in range(4)]
        result = analyze_recurring_issues(history)
        assert len(result) == 1


class TestAnalyzeRecurringIssuesPriority:
    """Priority depends on whether any recurring CVE is CRITICAL."""

    def test_critical_recurring_gives_medium_priority(self):
        history = [_scan(f"scan{i}", [_scan_finding(cve_id="CVE-2024-001", severity="CRITICAL")]) for i in range(3)]
        rec = analyze_recurring_issues(history)[0]
        assert rec.priority == Priority.MEDIUM

    def test_high_recurring_gives_low_priority(self):
        history = [_scan(f"scan{i}", [_scan_finding(cve_id="CVE-2024-001", severity="HIGH")]) for i in range(3)]
        rec = analyze_recurring_issues(history)[0]
        assert rec.priority == Priority.LOW

    def test_medium_recurring_gives_low_priority(self):
        history = [_scan(f"scan{i}", [_scan_finding(cve_id="CVE-2024-001", severity="MEDIUM")]) for i in range(3)]
        rec = analyze_recurring_issues(history)[0]
        assert rec.priority == Priority.LOW

    def test_mixed_critical_and_high_gives_medium_priority(self):
        history = [
            _scan(
                f"scan{i}",
                [
                    _scan_finding(cve_id="CVE-2024-001", severity="CRITICAL"),
                    _scan_finding(cve_id="CVE-2024-002", severity="HIGH"),
                ],
            )
            for i in range(3)
        ]
        rec = analyze_recurring_issues(history)[0]
        assert rec.priority == Priority.MEDIUM


class TestAnalyzeRecurringIssuesAffectedComponents:
    def test_affected_components_format(self):
        history = [_scan(f"scan{i}", [_scan_finding(cve_id="CVE-2024-001", component="lodash")]) for i in range(3)]
        rec = analyze_recurring_issues(history)[0]
        assert any("CVE-2024-001" in c and "lodash" in c for c in rec.affected_components)

    def test_affected_components_include_scan_count(self):
        history = [_scan(f"scan{i}", [_scan_finding(cve_id="CVE-2024-001")]) for i in range(3)]
        rec = analyze_recurring_issues(history)[0]
        assert any("3 scans" in c for c in rec.affected_components)


class TestAnalyzeRecurringIssuesNonVulnSkipped:
    def test_non_vuln_not_counted(self):
        non_vuln_finding = {
            "type": "license",
            "severity": "MEDIUM",
            "component": "pkg",
            "id": "lic-1",
            "details": {},
            "description": "License issue",
        }
        history = [_scan(f"scan{i}", [non_vuln_finding]) for i in range(5)]
        result = analyze_recurring_issues(history)
        assert len(result) == 0


class TestRecurringDetectionEndToEndWithPersistedSummary:
    """Recurring-vulnerability recs require the engine to persist a compact scan.findings_summary; exercises the real summary builder round-tripped through the Scan model."""

    @staticmethod
    def _aggregated_vuln(cve_id, severity="CRITICAL", component="pkg"):
        from app.models.finding import Finding

        return Finding(
            id=cve_id,
            type="vulnerability",
            severity=severity,
            component=component,
            version="1.0.0",
            description=f"Description for {cve_id}",
            scanners=["osv"],
            details={"cve_id": cve_id, "bulky": "x" * 5000},
        )

    def _persisted_summary_for_scan(self, scan_id, findings):
        """Run the engine's real prepare + summary builder, then round-trip through the Scan model as the DB read path does."""
        from app.models.project import Scan
        from app.services.analysis.engine import (
            _build_findings_summary,
            _prepare_finding_records,
        )

        _, vulnerability_findings = _prepare_finding_records(findings, scan_id, "proj-1", None)
        summary = _build_findings_summary(vulnerability_findings)
        # Scan.model_dump() must preserve the summary and it must validate as List[Finding].
        scan = Scan(id=scan_id, project_id="proj-1", branch="main", findings_summary=summary)
        return scan.model_dump()

    def test_recurring_fires_across_three_completed_scans(self):
        history = [
            self._persisted_summary_for_scan(f"scan{i}", [self._aggregated_vuln("CVE-2024-999", component="lodash")])
            for i in range(3)
        ]
        # The persisted summary must be non-empty.
        assert all(s["findings_summary"] for s in history)
        result = analyze_recurring_issues(history)
        assert len(result) == 1
        assert result[0].type == RecommendationType.RECURRING_VULNERABILITY
        assert any("CVE-2024-999" in c and "lodash" in c for c in result[0].affected_components)

    def test_one_off_does_not_fire(self):
        history = [self._persisted_summary_for_scan("scan1", [self._aggregated_vuln("CVE-2024-999")])]
        assert analyze_recurring_issues(history) == []

    def test_summary_is_bounded_and_compact(self):
        from app.services.analysis.engine import (
            _build_findings_summary,
            _prepare_finding_records,
        )

        findings = [self._aggregated_vuln(f"CVE-2024-{i:04d}") for i in range(600)]
        _, vulnerability_findings = _prepare_finding_records(findings, "scanX", "proj-1", None)
        summary = _build_findings_summary(vulnerability_findings)
        # Capped well under Mongo's 16MB doc limit.
        assert len(summary) == 500
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
            severity="MEDIUM",
            component="pkg",
            description="GPL",
            scanners=["licensecheck"],
        )
        vuln = self._aggregated_vuln("CVE-2024-001")
        _findings_to_insert, vulnerability_findings = _prepare_finding_records(
            [license_finding, vuln], "scanY", "proj-1", None
        )
        summary = _build_findings_summary(vulnerability_findings)
        assert len(summary) == 1
        assert summary[0]["type"] == "vulnerability"
