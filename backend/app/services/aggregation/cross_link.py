"""Pure cross-linking helpers extracted from ResultAggregator.

These functions only mutate the *Finding* objects passed in; they do not
touch any aggregator state, which makes them easy to test in isolation.
"""

from __future__ import annotations

from app.models.finding import Finding, FindingType


def cross_link_pair(f1: Finding, f2: Finding) -> None:
    """Add cross-references between two findings."""
    if f2.id not in f1.related_findings:
        f1.related_findings.append(f2.id)
    if f1.id not in f2.related_findings:
        f2.related_findings.append(f1.id)


def add_context_to_vulnerability(vuln_finding: Finding, other_finding: Finding) -> None:
    """
    Adds contextual information from other finding types to a vulnerability finding.
    """
    if vuln_finding.type != FindingType.VULNERABILITY:
        return

    if other_finding.type == FindingType.OUTDATED:
        if "outdated_info" not in vuln_finding.details:
            vuln_finding.details["outdated_info"] = {
                "is_outdated": True,
                "current_version": other_finding.version,
                "latest_version": other_finding.details.get("fixed_version"),
                "message": other_finding.description,
            }

    elif other_finding.type == FindingType.QUALITY:
        if "quality_info" not in vuln_finding.details:
            quality_issues = other_finding.details.get("quality_issues", [])
            vuln_finding.details["quality_info"] = {
                "has_quality_issues": True,
                "issue_count": len(quality_issues),
                "overall_score": other_finding.details.get("overall_score"),
                "has_maintenance_issues": other_finding.details.get("has_maintenance_issues", False),
                "quality_finding_id": other_finding.id,
            }

    elif other_finding.type == FindingType.LICENSE:
        if "license_info" not in vuln_finding.details:
            vuln_finding.details["license_info"] = {
                "has_license_issue": True,
                "license": other_finding.details.get("license"),
                "category": other_finding.details.get("category"),
                "license_finding_id": other_finding.id,
            }

    elif other_finding.type == FindingType.EOL:
        if "eol_info" not in vuln_finding.details:
            vuln_finding.details["eol_info"] = {
                "is_eol": True,
                "eol_date": other_finding.details.get("eol_date"),
                "cycle": other_finding.details.get("cycle"),
                "latest_version": other_finding.details.get("fixed_version"),
                "eol_finding_id": other_finding.id,
            }
