"""Quality-finding presentation helpers extracted from ResultAggregator.

Currently exposes ``update_quality_description`` which rewrites a finding's
``description`` to summarise the aggregated ``quality_issues`` list.
"""

from __future__ import annotations

from app.models.finding import Finding


def update_quality_description(finding: Finding) -> None:
    """Updates the description of an aggregated quality finding."""
    quality_issues = finding.details.get("quality_issues", [])
    count = len(quality_issues)

    if count == 0:
        finding.description = "Quality issues detected"
        return

    if count == 1:
        # Use the original description from the single issue
        finding.description = quality_issues[0].get("description", "Quality issue detected")
        return

    # Multiple issues - create summary
    parts = []

    # Check for scorecard
    scorecard_issues = [q for q in quality_issues if q.get("type") == "scorecard"]
    if scorecard_issues:
        score = scorecard_issues[0].get("details", {}).get("overall_score")
        if score is not None:
            parts.append(f"Scorecard: {score:.1f}/10")

    # Check for maintainer risk
    maint_issues = [q for q in quality_issues if q.get("type") == "maintainer_risk"]
    if maint_issues:
        risks = maint_issues[0].get("details", {}).get("risks", [])
        if risks:
            parts.append(f"{len(risks)} maintainer risks")

    # Other issues
    other_count = count - len(scorecard_issues) - len(maint_issues)
    if other_count > 0:
        parts.append(f"{other_count} other issues")

    finding.description = " | ".join(parts) if parts else f"{count} quality issues"
