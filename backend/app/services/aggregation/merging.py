"""Pure merge helpers for ResultAggregator.

These functions only mutate the *inputs* (lists / Finding objects) passed
in; they do not depend on aggregator instance state. The class keeps thin
private wrappers so existing tests that call ``self._merge_sast_findings``
etc. continue to work.
"""

from __future__ import annotations

from typing import Any, List, Optional

from app.core.constants import AGG_KEY_SAST, get_severity_value
from app.models.finding import Finding, FindingType
from app.schemas.finding import VulnerabilityEntry
from app.services.aggregation.versions import resolve_fixed_versions


def merge_sast_findings(findings: List[Finding]) -> Optional[Finding]:
    """
    Merges a list of SAST findings into a single finding with a list of individual results.
    Similar to how vulnerabilities or quality issues are aggregated.
    """
    if not findings:
        return None

    # Use the first finding as the base
    base = findings[0]

    # Prepare the container logic
    merged_details = {
        "sast_findings": [],
        # Keep common top-level fields for easy access/compatibility
        "file": base.component,
        "line": base.details.get("line") or base.details.get("start", {}).get("line"),
        # Merge lists
        "cwe_ids": [],
        "category_groups": [],
        "owasp": [],
    }

    merged_scanners = set()
    max_severity_val = 0
    max_severity = "INFO"

    all_descriptions = []

    for f in findings:
        # Update severity
        s_val = get_severity_value(f.severity)
        if s_val > max_severity_val:
            max_severity_val = s_val
            max_severity = f.severity

        # Collect scanners
        for s in f.scanners:
            merged_scanners.add(s)

        # Parse individual entry
        entry = {
            "id": f.details.get("rule_id", "unknown"),  # specific rule id
            "scanner": f.scanners[0] if f.scanners else "unknown",
            "severity": f.severity,
            "title": f.details.get("title", f.description[:50]),
            "description": f.description,
            "details": f.details,  # Keep full details
        }
        merged_details["sast_findings"].append(entry)

        # Aggregate sets
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

    # Determine a merged description
    if len(findings) > 1:
        # If rules are same (due to grouping), use the first one's description but indicate multi-scanner
        # Since we now group by rule_id, the description should be consistent.
        description = base.description
        # Append scanner count if multiple scanners found it
        if len(merged_scanners) > 1:
            description += f" (Confirmed by {len(merged_scanners)} scanners)"
    else:
        description = base.description

    # Construct new Finding
    return Finding(
        id=(
            base.id if len(findings) == 1 else f"{AGG_KEY_SAST}-{base.component}-{merged_details['line']}"
        ),  # create stable ID for group
        type=FindingType.SAST,
        severity=max_severity,
        component=base.component,
        version=base.version,
        description=description,
        scanners=list(merged_scanners),
        details=merged_details,
        found_in=base.found_in,  # simplistic merge
        aliases=([f.id for f in findings if f.id != base.id] if len(findings) > 1 else base.aliases),
    )


def merge_vulnerability_into_list(target_list: List[Any], source_entry: VulnerabilityEntry) -> None:
    """
    Merges a source vulnerability entry into a target list, handling deduplication by ID and Aliases.
    """
    match_found = False
    s_ids = set([source_entry["id"]] + source_entry.get("aliases", []))

    for tv in target_list:
        t_ids = set([tv["id"]] + tv.get("aliases", []))

        if not s_ids.isdisjoint(t_ids):
            # Match found! Merge details
            match_found = True

            # Merge Scanners
            tv["scanners"] = list(set(tv.get("scanners", []) + source_entry.get("scanners", [])))

            # Merge Aliases
            all_aliases = set(tv.get("aliases", []) + source_entry.get("aliases", []))
            if source_entry["id"] != tv["id"]:
                all_aliases.add(source_entry["id"])
            tv["aliases"] = list(all_aliases)

            # Merge Severity (Max)
            tv_sev_val = get_severity_value(tv.get("severity"))
            sv_sev_val = get_severity_value(source_entry.get("severity"))
            if sv_sev_val > tv_sev_val:
                tv["severity"] = source_entry["severity"]

            # Description merge (prefer longer)
            if len(source_entry.get("description", "")) > len(tv.get("description", "")):
                tv["description"] = source_entry["description"]
                tv["description_source"] = source_entry.get("description_source", "unknown")

            # Fixed version merge (prefer non-empty)
            if not tv.get("fixed_version") and source_entry.get("fixed_version"):
                tv["fixed_version"] = source_entry["fixed_version"]

            # CVSS merge (prefer higher)
            if source_entry.get("cvss_score") and (
                not tv.get("cvss_score") or source_entry["cvss_score"] > tv["cvss_score"]
            ):
                tv["cvss_score"] = source_entry["cvss_score"]
                tv["cvss_vector"] = source_entry.get("cvss_vector")

            # References merge (combine references and urls, deduplicate)
            tv_refs = set(tv.get("references", []) or [])
            sv_refs = set(source_entry.get("references", []) or [])
            # Also include urls from nested details if present
            tv_urls = set(tv.get("details", {}).get("urls", []) or [])
            sv_urls = set(source_entry.get("details", {}).get("urls", []) or [])
            all_refs = tv_refs | sv_refs | tv_urls | sv_urls
            tv["references"] = list(all_refs)
            # Remove urls from nested details as they're now in references
            if "details" in tv and "urls" in tv["details"]:
                del tv["details"]["urls"]

            # Merge other details (selectively)
            for key in ["cwe_ids", "published_date", "last_modified_date"]:
                # Check source details
                val = source_entry.get("details", {}).get(key)
                if not val:
                    continue

                # Ensure target has details dict
                if "details" not in tv:
                    tv["details"] = {}

                # Update if missing in target
                if key not in tv["details"] or not tv["details"][key]:
                    tv["details"][key] = val

            break

    if not match_found:
        target_list.append(source_entry)


def merge_findings_data(target: Finding, source: Finding) -> None:
    """Merges data from source finding into target finding."""
    # 1. Scanners
    target.scanners = list(set(target.scanners + source.scanners))

    # 2. Severity (Max)
    t_sev = get_severity_value(target.severity) or 0
    s_sev = get_severity_value(source.severity) or 0
    if s_sev > t_sev:
        target.severity = source.severity

    # 3. Found In
    target.found_in = list(set(target.found_in + source.found_in))

    # 4. Aliases
    target.aliases = list(set(target.aliases + source.aliases))
    if source.id != target.id and source.id not in target.aliases:
        target.aliases.append(source.id)

    # 5. Details (Vulnerabilities)
    # Merge vulnerabilities list, handling aliases to avoid duplicates
    t_vulns_list = target.details.get("vulnerabilities", [])
    s_vulns_list = source.details.get("vulnerabilities", [])

    for sv in s_vulns_list:
        merge_vulnerability_into_list(t_vulns_list, sv)

    target.details["vulnerabilities"] = t_vulns_list

    # Recalculate top-level fixed version
    fvs = [v.get("fixed_version") for v in target.details["vulnerabilities"] if v.get("fixed_version")]
    target.details["fixed_version"] = resolve_fixed_versions(fvs)
