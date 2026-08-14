"""Cross-linking helpers that mutate Finding objects without touching aggregator state."""

from __future__ import annotations

from app.core.constants import get_severity_value
from app.models.finding import Finding, FindingType


def cross_link_pair(f1: Finding, f2: Finding) -> None:
    """Cross-reference two findings on the same package and exchange their context blocks."""
    if f2.id not in f1.related_findings:
        f1.related_findings.append(f2.id)
    if f1.id not in f2.related_findings:
        f2.related_findings.append(f1.id)

    for primary, other in ((f1, f2), (f2, f1)):
        add_context_to_vulnerability(primary, other)
        _add_vulnerability_context(primary, other)
        _record_additional_type(primary, other)


def _record_additional_type(finding: Finding, other: Finding) -> None:
    """List the other finding types this package carries, for the multi-type badge row."""
    if finding.type == other.type:
        return

    # use_enum_values=True stores the raw strings, so no .value here.
    other_type = str(other.type)
    severity = str(other.severity)
    types: list[dict[str, str]] = finding.details.setdefault("additional_finding_types", [])
    for entry in types:
        if entry["type"] == other_type:
            if get_severity_value(severity) > get_severity_value(entry["severity"]):
                entry["severity"] = severity
            return

    types.append({"type": other_type, "severity": severity})
    # Pairs are visited in list order; sort so the badge row does not depend on it.
    types.sort(key=lambda entry: entry["type"])


def _vulnerability_count(vuln_finding: Finding) -> int:
    entries = vuln_finding.details.get("vulnerabilities")
    return len(entries) if entries else 1


def _entry_severities(vuln_finding: Finding) -> list[str]:
    entries = vuln_finding.details.get("vulnerabilities") or []
    severities = [str(e.get("severity")) for e in entries if isinstance(e, dict) and e.get("severity")]
    return severities or [str(vuln_finding.severity)]


def _add_vulnerability_context(finding: Finding, vuln_finding: Finding) -> None:
    """Tell a non-vulnerability finding that its package also has vulnerabilities."""
    if finding.type == FindingType.VULNERABILITY or vuln_finding.type != FindingType.VULNERABILITY:
        return

    severities = _entry_severities(vuln_finding)
    info = finding.details.setdefault(
        "vulnerability_info",
        {"has_vulnerabilities": True, "vuln_count": 0, "critical_count": 0, "high_count": 0},
    )
    info["vuln_count"] += _vulnerability_count(vuln_finding)
    info["critical_count"] += sum(1 for s in severities if s == "CRITICAL")
    info["high_count"] += sum(1 for s in severities if s == "HIGH")


def add_context_to_vulnerability(vuln_finding: Finding, other_finding: Finding) -> None:
    """Add contextual info from other finding types onto a vulnerability finding."""
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

    elif other_finding.type == FindingType.EOL and "eol_info" not in vuln_finding.details:
        vuln_finding.details["eol_info"] = {
            "is_eol": True,
            "eol_date": other_finding.details.get("eol_date"),
            "cycle": other_finding.details.get("cycle"),
            "latest_version": other_finding.details.get("fixed_version"),
            "eol_finding_id": other_finding.id,
        }
