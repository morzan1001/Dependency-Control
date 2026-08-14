"""K4: the frontend renders details.additional_finding_types and details.vulnerability_info;
the aggregator has always known both relationships but wrote neither."""

from app.models.finding import Finding, FindingType, Severity
from app.services.aggregation import ResultAggregator
from app.services.aggregation.cross_link import cross_link_pair


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
