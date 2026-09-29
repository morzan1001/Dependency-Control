"""Stateless version-handling helpers used during aggregation."""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from operator import itemgetter
from typing import Any

VersionKey = tuple[tuple[int, int | str], ...]


def parse_version_key(v: str) -> VersionKey:
    """Parse a version into (type_flag, value) pairs so numeric parts always sort before string parts."""
    v = v.lower()
    v = v.removeprefix("v")

    parts: list[tuple[int, int | str]] = []
    for part in re.split(r"[^a-z0-9]+", v):
        if not part:
            continue
        for subpart in re.findall(r"[a-z]+|\d+", part):
            if subpart.isdigit():
                parts.append((0, int(subpart)))
            else:
                parts.append((1, subpart))
    return tuple(parts)


def split_fixed_versions(value: Any) -> list[str]:
    """The single versions of a stored fixed_version, which writers join with ", " per release line."""
    return [part for raw in str(value or "").split(",") if (part := raw.strip())]


def _upgrade_candidates(fixed_version: Any, installed_key: VersionKey) -> list[tuple[VersionKey, str]]:
    """One advisory's fix candidates; a fix below the installed release is another line's backport."""
    candidates = [(key, part) for part in split_fixed_versions(fixed_version) if (key := parse_version_key(part))]
    return [(key, c) for key, c in candidates if key >= installed_key] or candidates


def _major_sort_key(major: int | str) -> tuple[bool, int, str]:
    return isinstance(major, str), major if isinstance(major, int) else 0, str(major)


def aggregate_fixed_version(entries: Iterable[Mapping[str, Any]], installed_version: str | None) -> str | None:
    """The version per major line that fixes every advisory, e.g. "1.2.6, 2.0.1"; None when one has no fix."""
    installed_key = parse_version_key(installed_version or "")
    advisories = [_upgrade_candidates(entry.get("fixed_version"), installed_key) for entry in entries]
    by_major: dict[int | str, dict[int, list[tuple[VersionKey, str]]]] = {}
    for index, candidates in enumerate(advisories):
        for key, candidate in candidates:
            by_major.setdefault(key[0][1], {}).setdefault(index, []).append((key, candidate))
    line_fixes = [
        (major, max((min(fixes, key=itemgetter(0)) for fixes in per_advisory.values()), key=itemgetter(0))[1])
        for major, per_advisory in by_major.items()
        if len(per_advisory) == len(advisories)
    ]
    return ", ".join(fix for _, fix in sorted(line_fixes, key=lambda line: _major_sort_key(line[0]))) or None


def normalize_version(version: str | None) -> str:
    if not version:
        return "unknown"
    v = version.strip().lower()
    if v.startswith("go") and len(v) > 2 and v[2].isdigit():
        return v[2:]
    if v.startswith("v") and len(v) > 1 and v[1].isdigit():
        return v[1:]
    return v
