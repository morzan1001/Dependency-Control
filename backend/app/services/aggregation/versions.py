"""Pure version-handling helpers extracted from ResultAggregator.

These are stateless utilities used during aggregation:
  * parse_version_key   - split a version string into a comparable tuple
  * calculate_aggregated_fixed_version - choose best fix(es) across vulns
  * resolve_fixed_versions - thin alias kept for symmetry with the legacy API
  * normalize_version - strip common prefixes (``v``, ``go``)
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple, Union


def parse_version_key(v: str) -> Tuple[Tuple[int, Union[int, str]], ...]:
    """Helper to parse version string into a comparable tuple.

    Each element is a (type_flag, value) pair where type_flag=0 for numeric
    parts and type_flag=1 for string parts. This ensures safe cross-type
    comparison: numbers always sort before strings at the same position.

    Mixed alphanumeric tokens like "0a1" are further split into
    ("0", "a", "1") so that numeric and string parts never share a position.
    """
    # Remove common prefixes
    v = v.lower()
    if v.startswith("v"):
        v = v[1:]

    # Split by non-alphanumeric characters
    parts: List[Tuple[int, Union[int, str]]] = []
    for part in re.split(r"[^a-z0-9]+", v):
        if not part:
            continue
        # Further split mixed alphanumeric tokens (e.g. "0a1" -> "0", "a", "1")
        for subpart in re.findall(r"[a-z]+|\d+", part):
            if subpart.isdigit():
                parts.append((0, int(subpart)))
            else:
                parts.append((1, subpart))
    return tuple(parts)


def calculate_aggregated_fixed_version(fixed_versions_list: List[str]) -> Optional[str]:
    """
    Calculates the best fixed version(s) considering multiple vulnerabilities and major versions.
    Input: List of fixed version strings (e.g. ["1.2.5, 2.0.1", "1.2.6"])
    Output: String (e.g. "1.2.6, 2.0.1")
    """
    if not fixed_versions_list:
        return None

    # 1. Parse all available fixes
    major_buckets: Dict[Any, Any] = {}

    for i, fv_str in enumerate(fixed_versions_list):
        # Split by comma to handle "1.2.5, 2.0.1"
        candidates = [c.strip() for c in fv_str.split(",") if c.strip()]

        for cand in candidates:
            try:
                parsed = parse_version_key(cand)
                if not parsed:
                    continue

                # Use first element's value as major version bucket key
                # If it's a string (e.g. 'release'), it goes to its own bucket
                major = parsed[0][1] if len(parsed) > 0 else 0

                if major not in major_buckets:
                    major_buckets[major] = {}

                if i not in major_buckets[major]:
                    major_buckets[major][i] = []

                major_buckets[major][i].append((parsed, cand))
            except (ValueError, TypeError, IndexError):
                continue

    # 2. Find valid major versions (must cover ALL vulnerabilities)
    valid_majors = []
    num_vulns = len(fixed_versions_list)

    for major, vulns_map in major_buckets.items():
        # Check if this major version has a fix for every vulnerability
        if len(vulns_map) == num_vulns:
            # Find the MAX required version for this major line
            max_ver_tuple = None
            max_ver_str = None

            for _, fixes in vulns_map.items():
                # Sort fixes for this vuln by version tuple (ascending)
                fixes.sort(key=lambda x: x[0])
                best_fix_for_vuln = fixes[0]

                if max_ver_tuple is None or best_fix_for_vuln[0] > max_ver_tuple:
                    max_ver_tuple = best_fix_for_vuln[0]
                    max_ver_str = best_fix_for_vuln[1]

            valid_majors.append((major, max_ver_tuple, max_ver_str))

    # 3. Sort and format results
    if not valid_majors:
        return None

    # Sort by major version (try to sort numerically if possible)
    try:
        valid_majors.sort(key=lambda x: x[0] if isinstance(x[0], int) else str(x[0]))
    except TypeError:
        valid_majors.sort(key=lambda x: str(x[0]))

    return ", ".join([str(vm[2]) for vm in valid_majors if vm[2] is not None])


def resolve_fixed_versions(versions: List[str]) -> Optional[str]:
    """
    Resolves the best fixed version(s) considering multiple vulnerabilities and major versions.
    Replaces legacy _get_latest_version.
    """
    return calculate_aggregated_fixed_version(versions)


def normalize_version(version: str) -> str:
    if not version:
        return "unknown"
    v = version.strip().lower()
    # Handle go1.25.4 -> 1.25.4
    if v.startswith("go") and len(v) > 2 and v[2].isdigit():
        return v[2:]
    # Handle v1.25.4 -> 1.25.4
    if v.startswith("v") and len(v) > 1 and v[1].isdigit():
        return v[1:]
    return v
