"""A package's OpenSSF Scorecard reaches its other findings through the cross-link package group.

deps_dev keys its scorecard on the inventory name (Maven: the bare artifactId) while trivy
reports the group-qualified coordinate, so the group has to bridge the two spellings.
"""

from app.models.finding import Finding, FindingType, Severity
from app.services.aggregation import ResultAggregator
from app.services.analyzers.deps_dev import DepsDevAnalyzer


def _scorecard_issue(name: str, version: str, failing: tuple[str, ...] = ("Maintained",)) -> dict:
    scorecard = {
        "overallScore": 2.4,
        "date": "2026-08-01",
        "checks": [{"name": check, "score": 0} for check in failing],
        "repository": f"github.com/example/{name}",
    }
    issue = DepsDevAnalyzer._create_scorecard_issue(f"https://github.com/example/{name}", scorecard)
    return {**issue, "component": name, "version": version, "purl": f"pkg:npm/{name}@{version}"}


def _trivy_vulnerability(package: str, version: str) -> dict:
    return {"VulnerabilityID": "CVE-2026-1", "PkgName": package, "InstalledVersion": version, "Severity": "HIGH"}


def _findings(scorecard_issues: list[dict], trivy_vulnerabilities: list[dict], *extra: Finding) -> list[Finding]:
    aggregator = ResultAggregator()
    aggregator.aggregate("deps_dev", {"scorecard_issues": scorecard_issues, "package_metadata": {}})
    if trivy_vulnerabilities:
        aggregator.aggregate("trivy", {"Results": [{"Target": "app", "Vulnerabilities": trivy_vulnerabilities}]})
    for finding in extra:
        aggregator.add_finding(finding)
    return aggregator.get_findings()


def _vulnerabilities(findings: list[Finding]) -> list[Finding]:
    return [f for f in findings if f.type == FindingType.VULNERABILITY]


class TestScorecardReachesThePackagesVulnerability:
    def test_the_context_block(self):
        [vuln] = _vulnerabilities(
            _findings([_scorecard_issue("left-pad", "1.3.0")], [_trivy_vulnerability("left-pad", "1.3.0")])
        )

        assert vuln.details["scorecard_context"] == {
            "overall_score": 2.4,
            "project_url": "https://github.com/example/left-pad",
            "critical_issues": ["Maintained"],
            "maintenance_risk": True,
            "has_vulnerabilities_issue": False,
        }

    def test_a_failing_vulnerabilities_check_is_not_a_maintenance_risk(self):
        [vuln] = _vulnerabilities(
            _findings(
                [_scorecard_issue("left-pad", "1.3.0", failing=("Vulnerabilities",))],
                [_trivy_vulnerability("left-pad", "1.3.0")],
            )
        )

        assert vuln.details["scorecard_context"]["maintenance_risk"] is False
        assert vuln.details["scorecard_context"]["has_vulnerabilities_issue"] is True

    def test_a_bare_artifact_scorecard_reaches_a_group_qualified_vulnerability(self):
        [vuln] = _vulnerabilities(
            _findings(
                [_scorecard_issue("jackson-databind", "2.20.2")],
                [_trivy_vulnerability("com.fasterxml.jackson.core:jackson-databind", "2.20.2")],
            )
        )

        assert vuln.details["scorecard_context"]["overall_score"] == 2.4

    def test_the_quality_banner_leaves_the_score_to_the_scorecard_block(self):
        [vuln] = _vulnerabilities(
            _findings([_scorecard_issue("left-pad", "1.3.0")], [_trivy_vulnerability("left-pad", "1.3.0")])
        )

        assert vuln.details["quality_info"] == {
            "has_quality_issues": True,
            "issue_count": 1,
            "has_maintenance_issues": True,
        }


class TestScorecardIsNotGuessed:
    def test_an_artifact_name_two_groups_share_gets_no_scorecard(self):
        findings = _findings(
            [_scorecard_issue("core", "1.0.0")],
            [_trivy_vulnerability("a.b:core", "1.0.0"), _trivy_vulnerability("c.d:core", "1.0.0")],
        )

        vulns = _vulnerabilities(findings)
        assert [v.component for v in vulns] == ["a.b:core", "c.d:core"]
        assert all("scorecard_context" not in v.details for v in vulns)

    def test_a_file_finding_named_like_a_package_gets_no_scorecard(self):
        secret = Finding(
            id="SECRET-bin-rails",
            type=FindingType.SECRET,
            severity=Severity.HIGH,
            component="bin/rails",
            version="",
            description="leaked key",
            scanners=["trufflehog"],
        )

        findings = _findings([_scorecard_issue("rails", "7.0.0")], [], secret)

        assert "scorecard_context" not in next(f for f in findings if f.type == FindingType.SECRET).details

    def test_the_quality_aggregate_holding_the_scorecard_gets_no_copy_of_it(self):
        findings = _findings([_scorecard_issue("left-pad", "1.3.0")], [_trivy_vulnerability("left-pad", "1.3.0")])

        [quality] = [f for f in findings if f.type == FindingType.QUALITY]
        assert [entry["type"] for entry in quality.details["quality_issues"]] == ["scorecard"]
        assert "scorecard_context" not in quality.details
