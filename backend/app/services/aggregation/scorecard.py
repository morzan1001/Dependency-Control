"""Scorecard enrichment helper extracted from ResultAggregator.

The aggregator keeps a per-component scorecard cache and uses it to add
maintenance/quality context to other findings (especially vulnerabilities).
The cache itself remains aggregator state; this function takes it as an
explicit argument so it can be tested in isolation.
"""

from __future__ import annotations

from typing import Any, Dict, List

from app.models.finding import Finding, FindingType


def enrich_with_scorecard(findings: List[Finding], scorecard_cache: Dict[str, Dict[str, Any]]) -> None:
    """
    Enriches non-scorecard findings with scorecard data for the same component.
    This adds maintenance and quality context to vulnerability findings.
    """
    if not scorecard_cache:
        return

    for finding in findings:
        # Skip scorecard findings themselves
        if finding.type == FindingType.QUALITY and finding.id.startswith("SCORECARD-"):
            continue

        # Try to find scorecard data for this component
        component_key = f"{finding.component}@{finding.version}" if finding.version else finding.component
        scorecard_data = scorecard_cache.get(component_key)

        # Also try without version
        if not scorecard_data and finding.component:
            for key, data in scorecard_cache.items():
                if key.startswith(f"{finding.component}@"):
                    scorecard_data = data
                    break

        if scorecard_data:
            # Add scorecard context to finding details
            finding.details["scorecard_context"] = {
                "overall_score": scorecard_data.get("overall_score"),
                "project_url": scorecard_data.get("project_url"),
                "critical_issues": scorecard_data.get("critical_issues", []),
                "maintenance_risk": "Maintained" in scorecard_data.get("critical_issues", []),
                "has_vulnerabilities_issue": "Vulnerabilities" in scorecard_data.get("critical_issues", []),
            }

            # If this is a vulnerability in a poorly maintained package, consider upgrading severity
            if finding.type == FindingType.VULNERABILITY:
                score = scorecard_data.get("overall_score", 10)
                critical = scorecard_data.get("critical_issues", [])

                # Add warning flags
                if score < 4.0 or "Maintained" in critical:
                    finding.details["maintenance_warning"] = True
                    finding.details["maintenance_warning_text"] = (
                        "This package has a low OpenSSF Scorecard score ({:.1f}/10) "
                        "which may indicate maintenance or security concerns.".format(score)
                    )
