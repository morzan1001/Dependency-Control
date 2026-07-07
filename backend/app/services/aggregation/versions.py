"""Stateless version-handling helpers used during aggregation."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple, Union


def parse_version_key(v: str) -> Tuple[Tuple[int, Union[int, str]], ...]:
    """Parse a version into (type_flag, value) pairs so numeric parts always sort before string parts."""
    v = v.lower()
    if v.startswith("v"):
        v = v[1:]

    parts: List[Tuple[int, Union[int, str]]] = []
    for part in re.split(r"[^a-z0-9]+", v):
        if not part:
            continue
        for subpart in re.findall(r"[a-z]+|\d+", part):
            if subpart.isdigit():
                parts.append((0, int(subpart)))
            else:
                parts.append((1, subpart))
    return tuple(parts)


def calculate_aggregated_fixed_version(fixed_versions_list: List[str]) -> Optional[str]:
    """Pick the best fixed version(s) across vulnerabilities and major lines, e.g. ["1.2.5, 2.0.1", "1.2.6"] -> "1.2.6, 2.0.1"."""
    if not fixed_versions_list:
        return None

    major_buckets: Dict[Any, Any] = {}

    for i, fv_str in enumerate(fixed_versions_list):
        candidates = [c.strip() for c in fv_str.split(",") if c.strip()]

        for cand in candidates:
            try:
                parsed = parse_version_key(cand)
                if not parsed:
                    continue

                # Bucket by first element; a string first element (e.g. 'release') gets its own bucket.
                major = parsed[0][1] if len(parsed) > 0 else 0

                if major not in major_buckets:
                    major_buckets[major] = {}

                if i not in major_buckets[major]:
                    major_buckets[major][i] = []

                major_buckets[major][i].append((parsed, cand))
            except (ValueError, TypeError, IndexError):
                continue

    valid_majors = []
    num_vulns = len(fixed_versions_list)

    for major, vulns_map in major_buckets.items():
        # A major line is only valid if it fixes every vulnerability.
        if len(vulns_map) == num_vulns:
            max_ver_tuple = None
            max_ver_str = None

            for _, fixes in vulns_map.items():
                fixes.sort(key=lambda x: x[0])
                best_fix_for_vuln = fixes[0]

                if max_ver_tuple is None or best_fix_for_vuln[0] > max_ver_tuple:
                    max_ver_tuple = best_fix_for_vuln[0]
                    max_ver_str = best_fix_for_vuln[1]

            valid_majors.append((major, max_ver_tuple, max_ver_str))

    if not valid_majors:
        return None

    try:
        valid_majors.sort(key=lambda x: x[0] if isinstance(x[0], int) else str(x[0]))
    except TypeError:
        valid_majors.sort(key=lambda x: str(x[0]))

    return ", ".join([str(vm[2]) for vm in valid_majors if vm[2] is not None])


def resolve_fixed_versions(versions: List[str]) -> Optional[str]:
    """Resolve the best fixed version(s) across multiple vulnerabilities and major versions."""
    return calculate_aggregated_fixed_version(versions)


def normalize_version(version: str) -> str:
    if not version:
        return "unknown"
    v = version.strip().lower()
    if v.startswith("go") and len(v) > 2 and v[2].isdigit():
        return v[2:]
    if v.startswith("v") and len(v) > 1 and v[1].isdigit():
        return v[1:]
    return v
