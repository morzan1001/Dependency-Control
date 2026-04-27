"""Merge helpers for ResultAggregator that operate purely on their inputs."""

from __future__ import annotations

from typing import Any, List, Optional

from app.core.constants import AGG_KEY_SAST, get_severity_value
from app.models.finding import Finding, FindingType
from app.schemas.finding import VulnerabilityEntry
from app.services.aggregation.versions import resolve_fixed_versions


def merge_sast_findings(findings: List[Finding]) -> Optional[Finding]:
    """Merge a list of SAST findings into one finding holding the per-scanner entries."""
    if not findings:
        return None

    base = findings[0]

    merged_details = {
        "sast_findings": [],
        "file": base.component,
        "line": base.details.get("line") or base.details.get("start", {}).get("line"),
        "cwe_ids": [],
        "category_groups": [],
        "owasp": [],
    }

    merged_scanners = set()
    max_severity_val = 0
    max_severity = "INFO"

    all_descriptions = []

    for f in findings:
        s_val = get_severity_value(f.severity)
        if s_val > max_severity_val:
            max_severity_val = s_val
            max_severity = f.severity

        for s in f.scanners:
            merged_scanners.add(s)

        entry = {
            "id": f.details.get("rule_id", "unknown"),
            "scanner": f.scanners[0] if f.scanners else "unknown",
            "severity": f.severity,
            "title": f.details.get("title", f.description[:50]),
            "description": f.description,
            "details": f.details,
        }
        merged_details["sast_findings"].append(entry)

        cwe_ids = f.details.get("cwe_ids") or []
        for cwe in cwe_ids:
            if cwe not in merged_details["cwe_ids"]:
                merged_details["cwe_ids"].append(cwe)

        category_groups = f.details.get("category_groups") or []
        for cat in category_groups:
            if cat not in merged_details["category_groups"]:
                merged_details["category_groups"].append(cat)

        owasp = f.details.get("owasp") or []
        for item in owasp:
            if item not in merged_details["owasp"]:
                merged_details["owasp"].append(item)

        if f.description and f.description not in all_descriptions:
            all_descriptions.append(f.description)

    if len(findings) > 1:
        description = base.description
        if len(merged_scanners) > 1:
            description += f" (Confirmed by {len(merged_scanners)} scanners)"
    else:
        description = base.description

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


def merge_vulnerability_into_list(target_list: List[Any], source_entry: VulnerabilityEntry) -> None:
    """Merge a source vuln entry into target list, deduplicating by ID and aliases."""
    match_found = False
    s_ids = set([source_entry["id"]] + source_entry.get("aliases", []))

    for tv in target_list:
        t_ids = set([tv["id"]] + tv.get("aliases", []))

        if not s_ids.isdisjoint(t_ids):
            match_found = True

            tv["scanners"] = list(set(tv.get("scanners", []) + source_entry.get("scanners", [])))

            all_aliases = set(tv.get("aliases", []) + source_entry.get("aliases", []))
            if source_entry["id"] != tv["id"]:
                all_aliases.add(source_entry["id"])
            tv["aliases"] = list(all_aliases)

            tv_sev_val = get_severity_value(tv.get("severity"))
            sv_sev_val = get_severity_value(source_entry.get("severity"))
            if sv_sev_val > tv_sev_val:
                tv["severity"] = source_entry["severity"]

            # Prefer longer description.
            if len(source_entry.get("description", "")) > len(tv.get("description", "")):
                tv["description"] = source_entry["description"]
                tv["description_source"] = source_entry.get("description_source", "unknown")

            if not tv.get("fixed_version") and source_entry.get("fixed_version"):
                tv["fixed_version"] = source_entry["fixed_version"]

            if source_entry.get("cvss_score") and (
                not tv.get("cvss_score") or source_entry["cvss_score"] > tv["cvss_score"]
            ):
                tv["cvss_score"] = source_entry["cvss_score"]
                tv["cvss_vector"] = source_entry.get("cvss_vector")

            tv_refs = set(tv.get("references", []) or [])
            sv_refs = set(source_entry.get("references", []) or [])
            tv_urls = set(tv.get("details", {}).get("urls", []) or [])
            sv_urls = set(source_entry.get("details", {}).get("urls", []) or [])
            all_refs = tv_refs | sv_refs | tv_urls | sv_urls
            tv["references"] = list(all_refs)
            if "details" in tv and "urls" in tv["details"]:
                del tv["details"]["urls"]

            for key in ["cwe_ids", "published_date", "last_modified_date"]:
                val = source_entry.get("details", {}).get(key)
                if not val:
                    continue

                if "details" not in tv:
                    tv["details"] = {}

                if key not in tv["details"] or not tv["details"][key]:
                    tv["details"][key] = val

            break

    if not match_found:
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
