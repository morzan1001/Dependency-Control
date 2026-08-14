"""Merge helpers for ResultAggregator that operate purely on their inputs."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from app.core.constants import AGG_KEY_SAST, get_severity_value
from app.models.finding import Finding, FindingType
from app.schemas.finding import VulnerabilityEntry
from app.services.aggregation.versions import parse_version_key, resolve_fixed_versions


def _extend_unique(target: list[Any], items: list[Any]) -> None:
    """Append items to target list, skipping duplicates."""
    for item in items:
        if item not in target:
            target.append(item)


def _sast_entry(f: Finding) -> dict[str, Any]:
    """Build the per-scanner sast_findings entry from a single Finding."""
    return {
        "id": f.details.get("rule_id", "unknown"),
        "scanner": f.scanners[0] if f.scanners else "unknown",
        "severity": f.severity,
        "title": f.details.get("title", f.description[:50]),
        "description": f.description,
        "details": f.details,
    }


def merge_sast_findings(findings: list[Finding]) -> Finding | None:
    """Merge a list of SAST findings into one finding holding the per-scanner entries."""
    if not findings:
        return None

    base = findings[0]

    merged_details: dict[str, Any] = {
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
        scanners=sorted(merged_scanners),
        details=merged_details,
        found_in=base.found_in,
        aliases=(sorted({f.id for f in findings if f.id != base.id}) if len(findings) > 1 else base.aliases),
    )


def _entry_ids(entry: Mapping[str, Any]) -> set[str]:
    """All ids under which this entry is known: id, aliases, and any resolved CVE."""
    candidates = [entry.get("id"), entry.get("resolved_cve"), *(entry.get("aliases") or [])]
    return {c for c in candidates if c}


def _canonical_id(a: str, b: str) -> str:
    """Prefer CVE ids over other schemes so the surviving id is analyzer-order independent."""
    return min(a, b, key=lambda vuln_id: (not vuln_id.startswith("CVE-"), vuln_id))


def _merge_vuln_ids_and_severity(tv: dict[str, Any], source_entry: VulnerabilityEntry) -> None:
    """Merge scanners, aliases, and severity (using the maximum)."""
    tv["scanners"] = sorted(set(tv.get("scanners", []) + source_entry.get("scanners", [])))

    all_ids = set(tv.get("aliases", [])) | set(source_entry.get("aliases", [])) | {tv["id"], source_entry["id"]}
    tv["id"] = _canonical_id(tv["id"], source_entry["id"])
    tv["aliases"] = sorted(all_ids - {tv["id"]})

    if get_severity_value(source_entry.get("severity")) > get_severity_value(tv.get("severity")):
        tv["severity"] = source_entry["severity"]


def _merge_vuln_description(tv: dict[str, Any], source_entry: VulnerabilityEntry) -> None:
    """Prefer the longer description; equal lengths fall back to sort order to stay commutative."""
    theirs, ours = source_entry.get("description", ""), tv.get("description", "")
    if (len(theirs), ours) > (len(ours), theirs):
        tv["description"] = theirs
        tv["description_source"] = source_entry.get("description_source", "unknown")


def _merged_fixed_version(a: Any, b: Any) -> str | None:
    """Union both comma-separated version lists in semantic order, so the result is arrival-order independent."""
    versions = {v.strip() for value in (a, b) if value for v in str(value).split(",")}
    versions.discard("")
    if not versions:
        return None
    return ", ".join(sorted(versions, key=lambda v: (parse_version_key(v), v)))


def _merge_vuln_fix_and_cvss(tv: dict[str, Any], source_entry: VulnerabilityEntry) -> None:
    """Merge fixed_version (union of candidates) and CVSS (taking the higher score)."""
    merged_fix = _merged_fixed_version(tv.get("fixed_version"), source_entry.get("fixed_version"))
    if merged_fix is not None:
        tv["fixed_version"] = merged_fix

    theirs, ours = source_entry.get("cvss_score"), tv.get("cvss_score")
    if theirs and (not ours or (theirs, str(source_entry.get("cvss_vector"))) > (ours, str(tv.get("cvss_vector")))):
        tv["cvss_score"] = theirs
        tv["cvss_vector"] = source_entry.get("cvss_vector")


def _merge_vuln_references(tv: dict[str, Any], source_entry: VulnerabilityEntry) -> None:
    """Union references from both entries."""
    tv_refs = set(tv.get("references", []) or [])
    sv_refs = set(source_entry.get("references", []) or [])
    tv["references"] = sorted(tv_refs | sv_refs)


def _merge_vuln_detail_fields(tv: dict[str, Any], source_entry: VulnerabilityEntry, source_first: bool) -> None:
    """Union the per-scanner detail blobs; a value conflict is settled by scanner name."""
    source_details = source_entry.get("details") or {}
    if not source_details:
        return
    target_details = tv.setdefault("details", {})
    for key, value in source_details.items():
        if not value:
            continue
        current = target_details.get(key)
        if not current:
            target_details[key] = value
        elif key == "fixed_version":
            target_details[key] = _merged_fixed_version(current, value)
        elif isinstance(current, list) and isinstance(value, list):
            target_details[key] = sorted({*current, *value}, key=str)
        elif source_first and current != value:
            target_details[key] = value


# Keys with dedicated merge logic; everything else is gap-filled from the absorbed entry.
_EXPLICITLY_MERGED_KEYS = frozenset(
    {
        "id",
        "aliases",
        "scanners",
        "severity",
        "description",
        "description_source",
        "fixed_version",
        "cvss_score",
        "cvss_vector",
        "references",
        "details",
    }
)


def _fill_missing_fields(tv: dict[str, Any], source_entry: VulnerabilityEntry) -> None:
    """Carry enrichment fields (resolved_cve, EPSS/KEV, advisory URL, ...) from an absorbed duplicate."""
    for key, value in source_entry.items():
        if key in _EXPLICITLY_MERGED_KEYS or value is None:
            continue
        if tv.get(key) is None:
            tv[key] = value


def _reporting_scanner(entry: Any) -> str:
    """Lowest scanner name of an entry; the total order settles detail conflicts commutatively."""
    return min(str(s) for s in (entry.get("scanners") or ["~"]))


def _absorb_entry(tv: dict[str, Any], source_entry: VulnerabilityEntry) -> None:
    """Fold source_entry into tv, which then represents both."""
    source_first = _reporting_scanner(source_entry) < _reporting_scanner(tv)
    _merge_vuln_ids_and_severity(tv, source_entry)
    _merge_vuln_description(tv, source_entry)
    _merge_vuln_fix_and_cvss(tv, source_entry)
    _merge_vuln_references(tv, source_entry)
    _merge_vuln_detail_fields(tv, source_entry, source_first)
    _fill_missing_fields(tv, source_entry)


def dedupe_vulnerability_entries(entries: list[Any]) -> None:
    """Fold together entries whose id/alias sets intersect, re-running until no pair overlaps."""
    changed = True
    while changed:
        changed = False
        i = 0
        while i < len(entries):
            ids_i = _entry_ids(entries[i])
            j = i + 1
            while j < len(entries):
                if ids_i.isdisjoint(_entry_ids(entries[j])):
                    j += 1
                    continue
                _absorb_entry(entries[i], entries.pop(j))
                ids_i = _entry_ids(entries[i])
                changed = True
            i += 1


def merge_vulnerability_into_list(target_list: list[Any], source_entry: VulnerabilityEntry) -> None:
    """Merge a source vuln entry into target list, deduplicating by ID and aliases."""
    s_ids = _entry_ids(source_entry)

    for tv in target_list:
        if s_ids.isdisjoint(_entry_ids(tv)):
            continue

        _absorb_entry(tv, source_entry)
        # Aliases gained from the source can newly link tv with other entries in the list.
        dedupe_vulnerability_entries(target_list)
        return

    target_list.append(source_entry)


def merge_findings_data(target: Finding, source: Finding) -> None:
    """Merge data from source finding into target finding."""
    target.scanners = sorted(set(target.scanners + source.scanners))

    t_sev = get_severity_value(target.severity) or 0
    s_sev = get_severity_value(source.severity) or 0
    if s_sev > t_sev:
        target.severity = source.severity

    target.found_in = sorted(set(target.found_in + source.found_in))

    target.aliases = sorted(set(target.aliases + source.aliases) | ({source.id} if source.id != target.id else set()))

    t_vulns_list = target.details.get("vulnerabilities", [])
    s_vulns_list = source.details.get("vulnerabilities", [])

    for sv in s_vulns_list:
        merge_vulnerability_into_list(t_vulns_list, sv)

    target.details["vulnerabilities"] = t_vulns_list

    fvs = [v.get("fixed_version") for v in target.details["vulnerabilities"] if v.get("fixed_version")]
    target.details["fixed_version"] = resolve_fixed_versions(fvs)
