"""Merge helpers for ResultAggregator that operate purely on their inputs."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from app.core.constants import AGG_KEY_SAST, get_severity_value
from app.models.finding import Finding, FindingType
from app.schemas.finding import VulnerabilityEntry
from app.services.aggregation.versions import resolve_fixed_versions


def _extend_unique(target: List[Any], items: List[Any]) -> None:
    """Append items to target list, skipping duplicates."""
    for item in items:
        if item not in target:
            target.append(item)


def _sast_entry(f: Finding) -> Dict[str, Any]:
    """Build the per-scanner sast_findings entry from a single Finding."""
    return {
        "id": f.details.get("rule_id", "unknown"),
        "scanner": f.scanners[0] if f.scanners else "unknown",
        "severity": f.severity,
        "title": f.details.get("title", f.description[:50]),
        "description": f.description,
        "details": f.details,
    }


def merge_sast_findings(findings: List[Finding]) -> Optional[Finding]:
    """Merge a list of SAST findings into one finding holding the per-scanner entries."""
    if not findings:
        return None

    base = findings[0]

    merged_details: Dict[str, Any] = {
        "sast_findings": [],
        "file": base.component,
        "line": base.details.get("line") or base.details.get("start", {}).get("line"),
        "cwe_ids": [],
        "category_groups": [],
        "owasp": [],
    }

    merged_scanners: set = set()
    max_severity_val = 0
    max_severity = "INFO"

    for f in findings:
        s_val = get_severity_value(f.severity)
        if s_val > max_severity_val:
            max_severity_val = s_val
            max_severity = f.severity

        merged_scanners.update(f.scanners)
        merged_details["sast_findings"].append(_sast_entry(f))
        _extend_unique(merged_details["cwe_ids"], f.details.get("cwe_ids") or [])
        _extend_unique(merged_details["category_groups"], f.details.get("category_groups") or [])
        _extend_unique(merged_details["owasp"], f.details.get("owasp") or [])

    description = base.description
    if len(findings) > 1 and len(merged_scanners) > 1:
        description += f" (Confirmed by {len(merged_scanners)} scanners)"

    return Finding(
        id=(base.id if len(findings) == 1 else f"{AGG_KEY_SAST}-{base.component}-{merged_details['line']}"),
        type=FindingType.SAST,
        severity=max_severity,
        component=base.component,
        version=base.version,
        description=description,
        scanners=list(merged_scanners),
        details=merged_details,
        found_in=base.found_in,
        aliases=([f.id for f in findings if f.id != base.id] if len(findings) > 1 else base.aliases),
    )


def _merge_vuln_ids_and_severity(tv: Dict[str, Any], source_entry: VulnerabilityEntry) -> None:
    """Merge scanners, aliases, and severity (using the maximum)."""
    tv["scanners"] = list(set(tv.get("scanners", []) + source_entry.get("scanners", [])))

    all_aliases = set(tv.get("aliases", []) + source_entry.get("aliases", []))
    if source_entry["id"] != tv["id"]:
        all_aliases.add(source_entry["id"])
    tv["aliases"] = list(all_aliases)

    if get_severity_value(source_entry.get("severity")) > get_severity_value(tv.get("severity")):
        tv["severity"] = source_entry["severity"]


def _merge_vuln_description(tv: Dict[str, Any], source_entry: VulnerabilityEntry) -> None:
    """Prefer the longer description."""
    if len(source_entry.get("description", "")) > len(tv.get("description", "")):
        tv["description"] = source_entry["description"]
        tv["description_source"] = source_entry.get("description_source", "unknown")


def _merge_vuln_fix_and_cvss(tv: Dict[str, Any], source_entry: VulnerabilityEntry) -> None:
    """Merge fixed_version (filling gaps) and CVSS (taking the higher score)."""
    if not tv.get("fixed_version") and source_entry.get("fixed_version"):
        tv["fixed_version"] = source_entry["fixed_version"]

    if source_entry.get("cvss_score") and (not tv.get("cvss_score") or source_entry["cvss_score"] > tv["cvss_score"]):
        tv["cvss_score"] = source_entry["cvss_score"]
        tv["cvss_vector"] = source_entry.get("cvss_vector")


def _merge_vuln_references(tv: Dict[str, Any], source_entry: VulnerabilityEntry) -> None:
    """Union references from both entries, including legacy details.urls fields."""
    tv_refs = set(tv.get("references", []) or [])
    sv_refs = set(source_entry.get("references", []) or [])
    tv_urls = set(tv.get("details", {}).get("urls", []) or [])
    sv_urls = set(source_entry.get("details", {}).get("urls", []) or [])
    tv["references"] = list(tv_refs | sv_refs | tv_urls | sv_urls)
    if "details" in tv and "urls" in tv["details"]:
        del tv["details"]["urls"]


def _merge_vuln_detail_fields(tv: Dict[str, Any], source_entry: VulnerabilityEntry) -> None:
    """Fill in missing detail fields from the source entry."""
    for key in ("cwe_ids", "published_date", "last_modified_date"):
        val = source_entry.get("details", {}).get(key)
        if not val:
            continue
        if "details" not in tv:
            tv["details"] = {}
        if key not in tv["details"] or not tv["details"][key]:
            tv["details"][key] = val


def merge_vulnerability_into_list(target_list: List[Any], source_entry: VulnerabilityEntry) -> None:
    """Merge a source vuln entry into target list, deduplicating by ID and aliases."""
    s_ids = set([source_entry["id"]] + source_entry.get("aliases", []))

    for tv in target_list:
        t_ids = set([tv["id"]] + tv.get("aliases", []))
        if s_ids.isdisjoint(t_ids):
            continue

        _merge_vuln_ids_and_severity(tv, source_entry)
        _merge_vuln_description(tv, source_entry)
        _merge_vuln_fix_and_cvss(tv, source_entry)
        _merge_vuln_references(tv, source_entry)
        _merge_vuln_detail_fields(tv, source_entry)
        return

    target_list.append(source_entry)


def merge_findings_data(target: Finding, source: Finding) -> None:
    """Merge data from source finding into target finding."""
    target.scanners = list(set(target.scanners + source.scanners))

    t_sev = get_severity_value(target.severity) or 0
    s_sev = get_severity_value(source.severity) or 0
    if s_sev > t_sev:
        target.severity = source.severity

    target.found_in = list(set(target.found_in + source.found_in))

    target.aliases = list(set(target.aliases + source.aliases))
    if source.id != target.id and source.id not in target.aliases:
        target.aliases.append(source.id)

    t_vulns_list = target.details.get("vulnerabilities", [])
    s_vulns_list = source.details.get("vulnerabilities", [])

    for sv in s_vulns_list:
        merge_vulnerability_into_list(t_vulns_list, sv)

    target.details["vulnerabilities"] = t_vulns_list

    fvs = [v.get("fixed_version") for v in target.details["vulnerabilities"] if v.get("fixed_version")]
    target.details["fixed_version"] = resolve_fixed_versions(fvs)
