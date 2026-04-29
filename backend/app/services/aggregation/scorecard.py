"""Scorecard enrichment helper that adds maintenance/quality context to findings."""

from __future__ import annotations

from typing import Any, Dict, List

from app.models.finding import Finding, FindingType


def enrich_with_scorecard(findings: List[Finding], scorecard_cache: Dict[str, Dict[str, Any]]) -> None:
    """Enrich non-scorecard findings with scorecard context for the same component."""
    if not scorecard_cache:
        return

    for finding in findings:
        if finding.type == FindingType.QUALITY and finding.id.startswith("SCORECARD-"):
            continue

        component_key = f"{finding.component}@{finding.version}" if finding.version else finding.component
        scorecard_data = scorecard_cache.get(component_key)

        if not scorecard_data and finding.component:
            for key, data in scorecard_cache.items():
                if key.startswith(f"{finding.component}@"):
                    scorecard_data = data
                    break

        if scorecard_data:
            finding.details["scorecard_context"] = {
                "overall_score": scorecard_data.get("overall_score"),
                "project_url": scorecard_data.get("project_url"),
                "critical_issues": scorecard_data.get("critical_issues", []),
                "maintenance_risk": "Maintained" in scorecard_data.get("critical_issues", []),
                "has_vulnerabilities_issue": "Vulnerabilities" in scorecard_data.get("critical_issues", []),
            }

            if finding.type == FindingType.VULNERABILITY:
                score = scorecard_data.get("overall_score", 10)
                critical = scorecard_data.get("critical_issues", [])

                if score < 4.0 or "Maintained" in critical:
                    finding.details["maintenance_warning"] = True
                    finding.details["maintenance_warning_text"] = (
                        "This package has a low OpenSSF Scorecard score ({:.1f}/10) "
                        "which may indicate maintenance or security concerns.".format(score)
                    )
