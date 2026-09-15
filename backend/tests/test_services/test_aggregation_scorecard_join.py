"""Scorecard context joins the dependency-inventory name against a finding component.

deps_dev keys its scorecard on the inventory name (Maven: the bare artifactId, since the
group sits in its own dependency field) while an aggregated vulnerability finding now
carries the group-qualified coordinate, so the join has to bridge the two spellings.
"""

from app.models.finding import Finding, FindingType, Severity
from app.services.aggregation.scorecard import enrich_with_scorecard

SCORECARD = {
    "overall_score": 2.4,
    "failed_checks": [],
    "critical_issues": ["Maintained"],
    "project_url": "https://github.com/FasterXML/jackson-databind",
    "checks": [],
}


def _vuln(component: str, version: str) -> Finding:
    return Finding(
        id=f"{component}:{version}",
        type=FindingType.VULNERABILITY,
        severity=Severity.HIGH,
        component=component,
        version=version,
        description="",
        scanners=["trivy"],
        details={"vulnerabilities": [{"id": "CVE-2026-1", "severity": "HIGH"}]},
    )


class TestScorecardReachesRequalifiedComponents:
    def test_bare_scorecard_key_reaches_a_group_qualified_finding(self):
        finding = _vuln("com.fasterxml.jackson.core:jackson-databind", "2.20.2")

        enrich_with_scorecard([finding], {"jackson-databind@2.20.2": SCORECARD})

        assert finding.details["scorecard_context"]["overall_score"] == 2.4
        assert finding.details["maintenance_warning"] is True

    def test_exact_key_still_wins(self):
        finding = _vuln("jackson-databind", "2.20.2")
        other = {**SCORECARD, "overall_score": 9.1, "critical_issues": []}

        enrich_with_scorecard([finding], {"jackson-databind@2.20.2": other, "x:jackson-databind@2.20.2": SCORECARD})

        assert finding.details["scorecard_context"]["overall_score"] == 9.1

    def test_ambiguous_artifact_name_is_not_guessed(self):
        finding = _vuln("@angular/core", "21.1.5")

        enrich_with_scorecard(
            [finding],
            {"@angular-devkit/core@21.1.5": SCORECARD, "@messageformat/core@21.1.5": SCORECARD},
        )

        assert "scorecard_context" not in finding.details

    def test_a_scoped_npm_key_keeps_its_package_name(self):
        """The '@' that opens an npm scope is not the version separator."""
        finding = _vuln("core", "21.1.5")

        enrich_with_scorecard([finding], {"@angular/core@21.1.5": SCORECARD})

        assert finding.details["scorecard_context"]["project_url"] == SCORECARD["project_url"]


class TestScorecardContextFlags:
    def test_a_failing_maintained_check_is_the_maintenance_risk(self):
        finding = _vuln("left-pad", "1.3.0")

        enrich_with_scorecard([finding], {"left-pad@1.3.0": SCORECARD})

        context = finding.details["scorecard_context"]
        assert context["maintenance_risk"] is True
        assert context["has_vulnerabilities_issue"] is False

    def test_a_failing_vulnerabilities_check_is_not_a_maintenance_risk(self):
        finding = _vuln("left-pad", "1.3.0")
        vulnerable = {**SCORECARD, "critical_issues": ["Vulnerabilities"]}

        enrich_with_scorecard([finding], {"left-pad@1.3.0": vulnerable})

        context = finding.details["scorecard_context"]
        assert context["maintenance_risk"] is False
        assert context["has_vulnerabilities_issue"] is True
