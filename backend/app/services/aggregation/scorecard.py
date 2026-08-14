"""Scorecard enrichment helper that adds maintenance/quality context to findings."""

from __future__ import annotations

from typing import Any

from app.models.finding import Finding, FindingType
from app.services.aggregation.components import build_component_index, lookup_component


def _index_by_artifact(scorecard_cache: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Cache entries keyed by bare artifact name, dropping names claimed by several packages.

    deps_dev keys on the inventory name while a vulnerability finding carries the qualified
    coordinate; this resolves the two without attributing one package's score to another.
    """
    by_name: dict[str, dict[str, Any]] = {}
    for key, data in scorecard_cache.items():
        by_name[key.rsplit("@", 1)[0] if "@" in key else key] = data
    return build_component_index(by_name)


def enrich_with_scorecard(findings: list[Finding], scorecard_cache: dict[str, dict[str, Any]]) -> None:
    """Enrich non-scorecard findings with scorecard context for the same component."""
    if not scorecard_cache:
        return

    by_artifact = _index_by_artifact(scorecard_cache)

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

        if not scorecard_data and finding.component:
            scorecard_data = lookup_component(by_artifact, finding.component)

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
                        f"This package has a low OpenSSF Scorecard score ({score:.1f}/10) "
                        "which may indicate maintenance or security concerns."
                    )
