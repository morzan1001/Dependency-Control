"""Merge helpers for ResultAggregator that operate purely on their inputs."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from app.core.constants import max_severity
from app.core.cve import advisory_ids, entry_cves
from app.models.finding import Finding
from app.schemas.finding import VulnerabilityEntry
from app.services.aggregation.versions import VersionKey, parse_version_key, split_fixed_versions


def to_sast_aggregate(f: Finding) -> Finding:
    """Wrap one scanner's SAST finding in the persisted sast_findings shape."""
    entry = {
        "id": f.details.get("rule_id", "unknown"),
        "scanner": f.scanners[0],
        "severity": f.severity,
        "details": f.details,
    }
    line = f.details.get("start", {}).get("line")
    return f.model_copy(update={"details": {"sast_findings": [entry], "file": f.component, "line": line}})


def _same_advisory(a_ids: set[str], a: Mapping[str, Any], b: Mapping[str, Any]) -> bool:
    """Shared ids make one advisory unless led by different CVEs naming different sets (distro bundles alias CVEs)."""
    if a_ids.isdisjoint(advisory_ids(b)):
        return False
    cves_a, cves_b = entry_cves(a), entry_cves(b)
    return not cves_a or not cves_b or cves_a[0] == cves_b[0] or set(cves_a) == set(cves_b)


def _canonical_id(a: str, b: str) -> str:
    """Prefer CVE ids over other schemes so the surviving id is analyzer-order independent."""
    return min(a, b, key=lambda vuln_id: (not vuln_id.startswith("CVE-"), vuln_id))


def _merge_vuln_ids_and_severity(tv: dict[str, Any], source_entry: VulnerabilityEntry) -> None:
    """Merge scanners, aliases, and severity (using the maximum)."""
    tv["scanners"] = sorted(set(tv.get("scanners", []) + source_entry.get("scanners", [])))

    all_ids = set(tv.get("aliases", [])) | set(source_entry.get("aliases", [])) | {tv["id"], source_entry["id"]}
    tv["id"] = _canonical_id(tv["id"], source_entry["id"])
    tv["aliases"] = sorted(all_ids - {tv["id"]})

    merged = max_severity(tv.get("severity"), source_entry.get("severity"))
    if merged is not None:
        tv["severity"] = merged


def _merge_vuln_description(tv: dict[str, Any], source_entry: VulnerabilityEntry) -> None:
    """Prefer the longer description; equal lengths fall back to sort order to stay commutative."""
    theirs, ours = source_entry.get("description", ""), tv.get("description", "")
    if (len(theirs), ours) > (len(ours), theirs):
        tv["description"] = theirs


def _fix_candidates(value: Any) -> set[tuple[VersionKey, str]]:
    return {(parse_version_key(v), v) for v in split_fixed_versions(value)}


def _merged_fixed_version(a: Any, b: Any) -> str | None:
    """Both scanners' fixes, less those below the higher of their lowest fixes per release line (still vulnerable)."""
    sides = _fix_candidates(a), _fix_candidates(b)
    floor: dict[VersionKey, VersionKey] = {}
    for side in sides:
        for line, lowest in {key[:2]: key for key, _ in sorted(side, reverse=True)}.items():
            floor[line] = max(floor.get(line, lowest), lowest)
    return ", ".join(v for key, v in sorted(sides[0] | sides[1]) if key >= floor[key[:2]]) or None


def _merge_vuln_fix_and_cvss(tv: dict[str, Any], source_entry: VulnerabilityEntry) -> None:
    """Merge fixed_version (as _merged_fixed_version) and CVSS (taking the higher score)."""
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


def _detail_precedence(entry: Any) -> tuple[str, str]:
    """Total order over entries settling detail conflicts commutatively.

    Lowest scanner name first; alias-linked entries can share it, so the entry id decides.
    """
    return min(str(s) for s in (entry.get("scanners") or ["~"])), str(entry.get("id"))


def _absorb_entry(tv: dict[str, Any], source_entry: VulnerabilityEntry) -> None:
    """Fold source_entry into tv, which then represents both."""
    source_first = _detail_precedence(source_entry) < _detail_precedence(tv)
    _merge_vuln_ids_and_severity(tv, source_entry)
    _merge_vuln_description(tv, source_entry)
    _merge_vuln_fix_and_cvss(tv, source_entry)
    _merge_vuln_references(tv, source_entry)
    _merge_vuln_detail_fields(tv, source_entry, source_first)
    _fill_missing_fields(tv, source_entry)


def dedupe_vulnerability_entries(entries: list[Any]) -> None:
    """Fold each entry into the earliest kept entry of its advisory; an absorber is re-linked until nothing matches."""
    kept: list[Any] = []
    kept_by_id: dict[str, set[int]] = {}
    # Advisory matching is not transitive, so a fixed order decides which entry absorbs an ambiguous one.
    for entry in sorted(entries, key=_detail_precedence):
        position = len(kept)
        kept.append(entry)
        while True:
            ids = advisory_ids(kept[position])
            for vuln_id in ids:
                kept_by_id.setdefault(vuln_id, set()).add(position)
            sharing = sorted(
                {at for vuln_id in ids for at in kept_by_id[vuln_id] if at != position and kept[at] is not None}
            )
            match = next((at for at in sharing if _same_advisory(ids, kept[position], kept[at])), None)
            if match is None:
                break
            earlier, later = sorted((position, match))
            _absorb_entry(kept[earlier], kept[later])
            kept[later] = None
            position = earlier
    entries[:] = sorted((entry for entry in kept if entry is not None), key=lambda entry: str(entry.get("id")))


def absorb_header(target: Finding, other: Finding, source: str | None = None) -> None:
    """Fold other's scanners, severity and found_in (first-seen order) into target."""
    target.scanners = sorted(set(target.scanners) | set(other.scanners))
    target.severity = max_severity(target.severity, other.severity)
    target.found_in = list(dict.fromkeys([*target.found_in, *other.found_in, *([source] if source else [])]))


def merge_findings_data(target: Finding, source: Finding) -> None:
    """Merge data from source finding into target finding."""
    absorb_header(target, source)
    target.aliases = sorted(set(target.aliases + source.aliases) | ({source.id} if source.id != target.id else set()))

    target.details["vulnerabilities"].extend(source.details["vulnerabilities"])
