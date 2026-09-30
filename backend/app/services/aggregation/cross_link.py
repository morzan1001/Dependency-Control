"""Cross-linking helpers that mutate Finding objects without touching aggregator state."""

from __future__ import annotations

from typing import Any

from app.core.constants import get_severity_value, max_severity
from app.models.finding import Finding, FindingType
from app.schemas.finding_details import EolInfo, LicenseInfo, OutdatedInfo, QualityInfo, VulnerabilityContextInfo
from app.services.aggregation.versions import normalize_version


def cross_link_pair(f1: Finding, f2: Finding) -> None:
    """Cross-reference two findings on the same package; context blocks only pass between one version."""
    if f2.id not in f1.related_findings:
        f1.related_findings.append(f2.id)
    if f1.id not in f2.related_findings:
        f2.related_findings.append(f1.id)

    if not _same_version(f1.version, f2.version):
        return

    for primary, other in ((f1, f2), (f2, f1)):
        add_context_to_vulnerability(primary, other)
        _add_vulnerability_context(primary, other)
        _record_additional_type(primary, other)


def is_ahead_of_default(finding_type: str, details: dict[str, Any] | None) -> bool:
    """The outdated normalizer also mints installs newer than the registry default as OUTDATED."""
    return finding_type == FindingType.OUTDATED and bool((details or {}).get("ahead_of_default"))


def _record_additional_type(finding: Finding, other: Finding) -> None:
    """List the other finding types this package carries, for the multi-type badge row."""
    if finding.type == other.type or is_ahead_of_default(other.type, other.details):
        return

    # use_enum_values=True stores the raw strings, so no .value here.
    other_type = str(other.type)
    severity = str(other.severity)
    types: list[dict[str, str]] = finding.details.setdefault("additional_finding_types", [])
    for entry in types:
        if entry["type"] == other_type:
            entry["severity"] = max_severity(entry["severity"], severity)
            return

    types.append({"type": other_type, "severity": severity})
    # Pairs are visited in list order; sort so the badge row does not depend on it.
    types.sort(key=lambda entry: entry["type"])


def _same_version(a: str | None, b: str | None) -> bool:
    return not a or not b or normalize_version(a) == normalize_version(b)


def _vulnerability_context(entries: list[dict[str, Any]]) -> dict[str, int]:
    severities = [str(e["severity"]) for e in entries]
    return {
        "vuln_count": len(entries),
        "critical_count": severities.count("CRITICAL"),
        "high_count": severities.count("HIGH"),
    }


def _add_vulnerability_context(finding: Finding, vuln_finding: Finding) -> None:
    """Tell a non-vulnerability finding that its package also has vulnerabilities."""
    if finding.type == FindingType.VULNERABILITY or vuln_finding.type != FindingType.VULNERABILITY:
        return

    info = finding.details.setdefault("vulnerability_info", VulnerabilityContextInfo().model_dump())
    for key, count in _vulnerability_context(vuln_finding.details["vulnerabilities"]).items():
        info[key] += count


def refresh_vulnerability_info(records: list[dict[str, Any]]) -> None:
    """Recount each sibling's vulnerability_info once enrichment has folded GHSA-linked advisories."""
    by_id: dict[Any, list[dict[str, Any]]] = {}
    for record in records:
        by_id.setdefault(record.get("id"), []).append(record)
    for record in records:
        info = (record.get("details") or {}).get("vulnerability_info")
        related = record.get("related_findings") or []
        # A related record the ad-hoc cap cut can no longer be recounted.
        if not info or any(i not in by_id for i in related):
            continue
        contexts = [
            _vulnerability_context(vuln["details"]["vulnerabilities"])
            for i in related
            for vuln in by_id[i]
            if vuln.get("type") == FindingType.VULNERABILITY
            and _same_version(record.get("version"), vuln.get("version"))
        ]
        for key in ("vuln_count", "critical_count", "high_count"):
            info[key] = sum(context[key] for context in contexts)


def add_context_to_vulnerability(vuln_finding: Finding, other_finding: Finding) -> None:
    """Add contextual info from other finding types onto a vulnerability finding."""
    if vuln_finding.type != FindingType.VULNERABILITY:
        return

    details = vuln_finding.details
    other_details = other_finding.details
    if other_finding.type == FindingType.OUTDATED:
        if "outdated_info" not in details and not is_ahead_of_default(other_finding.type, other_details):
            details["outdated_info"] = OutdatedInfo(
                current_version=other_finding.version,
                latest_version=other_details.get("fixed_version"),
                message=other_finding.description,
            ).model_dump()

    elif other_finding.type == FindingType.QUALITY:
        if "quality_info" not in details:
            details["quality_info"] = QualityInfo(
                issue_count=len(other_details.get("quality_issues", [])),
                overall_score=other_details.get("overall_score"),
                has_maintenance_issues=other_details.get("has_maintenance_issues", False),
            ).model_dump()

    elif other_finding.type == FindingType.LICENSE:
        current = details.get("license_info")
        severity = str(other_finding.severity)
        # Pairs arrive in get_findings sort order, so a strict comparison leaves a tie to the lower id.
        if current is None or get_severity_value(severity) > get_severity_value(current["license_severity"]):
            details["license_info"] = LicenseInfo(
                license=other_details.get("license"),
                category=other_details.get("category"),
                license_severity=severity,
            ).model_dump()

    elif other_finding.type == FindingType.EOL and "eol_info" not in details:
        details["eol_info"] = EolInfo(
            eol_date=other_details.get("eol_date"),
            cycle=other_details.get("cycle"),
            latest_version=other_details.get("fixed_version"),
        ).model_dump()
