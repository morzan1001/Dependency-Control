"""Stateless version-handling helpers used during aggregation."""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any

# Flags that rank a tag below the end of a version, and both below one more number: 1.0-rc1 < 1.0 < 1.0.1.
_TAG, _END, _NUMBER = 0, 1, 2


def parse_version_key(v: str) -> tuple[tuple[int, int | str], ...]:
    """Parse a version into (flag, value) pairs that compare in version order; the first carries the major."""
    tokens = re.findall(r"[a-z]+|\d+", v.lower().removeprefix("v"))
    if not tokens:
        return ()
    parts: list[tuple[int, int | str]] = [(_NUMBER, int(t)) if t.isdigit() else (_TAG, t) for t in tokens]
    return (*parts, (_END, ""))


def _is_prerelease(key: tuple[tuple[int, int | str], ...]) -> bool:
    return any(flag == _TAG for flag, _ in key)


def newest_first(versions: Iterable[Any]) -> list[str]:
    """Versions ranked newest first; the raw string breaks ties, so a set-derived input orders the same every run."""
    return sorted((str(v) for v in versions), key=lambda v: (parse_version_key(v), v), reverse=True)


def calculate_aggregated_fixed_version(fixed_versions_list: list[str]) -> str | None:
    """Pick the best fixed version(s) across vulnerabilities and major lines, e.g. ["1.2.5, 2.0.1", "1.2.6"] -> "1.2.6, 2.0.1"."""
    if not fixed_versions_list:
        return None

    major_buckets: dict[Any, Any] = {}

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

            for fixes in vulns_map.values():
                # A prerelease fix counts only where the line offers no release fix.
                fixes.sort(key=lambda x: (_is_prerelease(x[0]), x[0]))
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


def resolve_fixed_versions(versions: list[str]) -> str | None:
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
