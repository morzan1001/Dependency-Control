"""K4: the frontend renders details.additional_finding_types and details.vulnerability_info;
the aggregator has always known both relationships but wrote neither."""

from app.models.finding import Finding, FindingType, Severity
from app.services.aggregation import ResultAggregator
from app.services.aggregation.cross_link import cross_link_pair
from app.services.analyzers.outdated import OutdatedAnalyzer


def _finding(finding_id: str, ftype: FindingType, severity: Severity, component: str, **details) -> Finding:
    return Finding(
        id=finding_id,
        type=ftype,
        severity=severity,
        component=component,
        version="1.0.0",
        description=f"{finding_id} on {component}",
        scanners=["test"],
        details=details,
    )


def _vuln(component: str = "lodash", entries: list[dict] | None = None) -> Finding:
    return _finding(
        f"{component}:1.0.0",
        FindingType.VULNERABILITY,
        Severity.CRITICAL,
        component,
        vulnerabilities=entries
        if entries is not None
        else [
            {"id": "CVE-2024-0001", "severity": "CRITICAL"},
            {"id": "CVE-2024-0002", "severity": "HIGH"},
        ],
    )


class TestAdditionalFindingTypes:
    def test_each_side_lists_the_other_type(self):
        vuln = _vuln()
        outdated = _finding("OUTDATED-lodash", FindingType.OUTDATED, Severity.MEDIUM, "lodash")

        cross_link_pair(vuln, outdated)

        assert vuln.details["additional_finding_types"] == [{"type": "outdated", "severity": "MEDIUM"}]
        assert outdated.details["additional_finding_types"] == [{"type": "vulnerability", "severity": "CRITICAL"}]

    def test_same_type_is_not_listed(self):
        a = _finding("LIC-A", FindingType.LICENSE, Severity.HIGH, "lodash")
        b = _finding("LIC-B", FindingType.LICENSE, Severity.LOW, "lodash")

        cross_link_pair(a, b)

        assert "additional_finding_types" not in a.details

    def test_repeated_type_keeps_the_highest_severity_and_sorts(self):
        vuln = _vuln()
        quality_low = _finding("Q-1", FindingType.QUALITY, Severity.LOW, "lodash")
        quality_high = _finding("Q-2", FindingType.QUALITY, Severity.HIGH, "lodash")
        eol = _finding("EOL-1", FindingType.EOL, Severity.MEDIUM, "lodash")

        cross_link_pair(vuln, quality_low)
        cross_link_pair(vuln, eol)
        cross_link_pair(vuln, quality_high)

        assert vuln.details["additional_finding_types"] == [
            {"type": "eol", "severity": "MEDIUM"},
            {"type": "quality", "severity": "HIGH"},
        ]


class TestVulnerabilityContext:
    def test_non_vulnerability_finding_learns_about_the_cves(self):
        vuln = _vuln()
        license_finding = _finding("LIC-GPL-3.0", FindingType.LICENSE, Severity.HIGH, "lodash")

        cross_link_pair(vuln, license_finding)

        assert license_finding.details["vulnerability_info"] == {
            "has_vulnerabilities": True,
            "vuln_count": 2,
            "critical_count": 1,
            "high_count": 1,
        }

    def test_vulnerability_findings_do_not_get_the_banner(self):
        a = _vuln("lodash")
        b = _finding("lodash:2.0.0", FindingType.VULNERABILITY, Severity.HIGH, "lodash")

        cross_link_pair(a, b)

        assert "vulnerability_info" not in a.details
        assert "vulnerability_info" not in b.details

    def test_counts_accumulate_over_several_vulnerability_documents(self):
        eol = _finding("EOL-lodash", FindingType.EOL, Severity.MEDIUM, "lodash")
        cross_link_pair(_vuln(), eol)
        cross_link_pair(_vuln(entries=[{"id": "CVE-2024-0003", "severity": "CRITICAL"}]), eol)

        assert eol.details["vulnerability_info"]["vuln_count"] == 3
        assert eol.details["vulnerability_info"]["critical_count"] == 2


class TestThroughTheAggregator:
    def test_keys_land_on_findings_returned_by_the_aggregator(self):
        agg = ResultAggregator()
        # Two scanner findings on one package merge into a single document with two entries.
        agg.add_finding(_finding("CVE-2024-0001", FindingType.VULNERABILITY, Severity.CRITICAL, "lodash"))
        agg.add_finding(_finding("CVE-2024-0002", FindingType.VULNERABILITY, Severity.HIGH, "lodash"))
        agg.add_finding(_finding("EOL-lodash", FindingType.EOL, Severity.MEDIUM, "lodash"))

        by_type = {f.type: f for f in agg.get_findings()}

        assert by_type[FindingType.EOL].details["vulnerability_info"] == {
            "has_vulnerabilities": True,
            "vuln_count": 2,
            "critical_count": 1,
            "high_count": 1,
        }
        assert by_type[FindingType.VULNERABILITY].details["additional_finding_types"] == [
            {"type": "eol", "severity": "MEDIUM"}
        ]


class TestContextStaysWithItsVersion:
    def test_two_versions_of_one_package_link_but_exchange_no_context(self):
        vuln = _vuln()
        vuln.version = "4.17.20"
        outdated = _finding("OUTDATED-lodash", FindingType.OUTDATED, Severity.INFO, "lodash", current_version="3.0.0")
        outdated.version = "3.0.0"

        cross_link_pair(vuln, outdated)

        assert outdated.id in vuln.related_findings
        assert vuln.id in outdated.related_findings
        for key in ("outdated_info", "eol_info", "vulnerability_info", "additional_finding_types"):
            assert key not in vuln.details
            assert key not in outdated.details

    def test_one_version_spelled_with_a_v_prefix_still_exchanges_context(self):
        vuln = _vuln()
        vuln.version = "v1.2.3"
        outdated = _finding("OUTDATED-lodash", FindingType.OUTDATED, Severity.INFO, "lodash")
        outdated.version = "1.2.3"

        cross_link_pair(vuln, outdated)

        assert outdated.details["vulnerability_info"]["vuln_count"] == 2


class TestAheadOfDefaultIsNotOutdated:
    """An install newer than the registry default is minted as OUTDATED with ahead_of_default set."""

    @staticmethod
    def _findings_by_type() -> dict:
        ahead: list = []
        component = {"name": "requests", "version": "1.0.0", "purl": "pkg:pypi/requests@1.0.0"}
        OutdatedAnalyzer()._classify_version(component, "0.9.0", [], ahead)
        agg = ResultAggregator()
        agg.aggregate("outdated_packages", {"outdated_dependencies": [], "ahead_of_default": ahead})
        agg.add_finding(_finding("CVE-2026-1", FindingType.VULNERABILITY, Severity.HIGH, "requests"))
        return {f.type: f for f in agg.get_findings()}

    def test_the_vulnerability_gets_no_outdated_banner_or_badge(self):
        vuln = self._findings_by_type()[FindingType.VULNERABILITY]

        assert "outdated_info" not in vuln.details
        assert "additional_finding_types" not in vuln.details

    def test_the_ahead_finding_still_learns_about_the_vulnerability(self):
        by_type = self._findings_by_type()
        ahead = by_type[FindingType.OUTDATED]

        assert ahead.id in by_type[FindingType.VULNERABILITY].related_findings
        assert ahead.details["additional_finding_types"] == [{"type": "vulnerability", "severity": "HIGH"}]
