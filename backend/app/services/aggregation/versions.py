from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from operator import itemgetter
from typing import Any

from packaging.version import InvalidVersion, Version

VersionKey = tuple[tuple[int, int | str], ...]

# Flags that give 1.0-rc1 < 1.0 < 1.0.post1 < 1.0.1: a prerelease tag, the end, any other tag, one more number.
_PRERELEASE, _END, _SUFFIX, _NUMBER = 0, 1, 2, 3

# Ranked to agree with both PEP 440 (dev < a < b < rc) and Maven (alpha < beta < milestone < rc < snapshot).
_PRERELEASE_RANK = {
    "dev": 0,
    "nightly": 0,
    "canary": 0,
    "experimental": 0,
    "alpha": 1,
    "a": 1,
    "beta": 2,
    "b": 2,
    "milestone": 3,
    "m": 3,
    "next": 4,
    "pre": 5,
    "preview": 5,
    "rc": 5,
    "cr": 5,
    "c": 5,
    "snapshot": 6,
}
# Maven's spellings of a plain release: 4.1.100.Final is 4.1.100.
_RELEASE_QUALIFIERS = frozenset({"final", "ga", "release"})


def _token_key(token: str, prev_char: str, next_char: str) -> tuple[int, int | str]:
    if token.isdigit():
        return (_NUMBER, int(token))
    # apk's -r revision repackages its version, so it ranks below a suffix of the version itself (2.4.1_p1).
    if token == "r" and prev_char == "-":
        return (_SUFFIX, "")
    rank = _PRERELEASE_RANK.get(token)
    # A lone letter is a prerelease only before a number (1.0a1); OpenSSL's 1.1.1a and Debian's +b6 follow their base.
    if rank is None or (len(token) == 1 and (prev_char == "+" or not next_char.isdigit())):
        return (_SUFFIX, token)
    return (_PRERELEASE, rank)


def parse_version_key(v: str) -> VersionKey:
    """Its first two pairs, major and minor, name the release line (a bare 2 ranks as 2.0)."""
    text = v.lower().split(":", 1)[-1].removeprefix("v")
    parts = [
        _token_key(m.group(), text[m.start() - 1 : m.start()], text[m.end() : m.end() + 1])
        for m in re.finditer(r"[a-z]+|\d+", text)
        if m.group() not in _RELEASE_QUALIFIERS
    ]
    release = next((i for i, (flag, _) in enumerate(parts) if flag != _NUMBER), len(parts))
    if release == 1:
        parts.insert(1, (_NUMBER, 0))
        release = 2
    while release > 2 and parts[release - 1] == (_NUMBER, 0):
        release -= 1
        del parts[release]
    if not parts:
        return ()
    return (*parts, (_END, ""))


def _is_prerelease(key: VersionKey) -> bool:
    return any(flag == _PRERELEASE for flag, _ in key)


# Strict-semver ecosystems mark every prerelease (Go pseudo-versions, npm "4.0.0-0") with "-" before any "+build".
_SEMVER_SYSTEMS = frozenset({"npm", "go", "cargo", "nuget"})


def is_stable_release(version: str, system: str) -> bool:
    if system in _SEMVER_SYSTEMS:
        return "-" not in version.split("+", 1)[0]
    try:
        return not Version(version).is_prerelease
    except InvalidVersion:
        # Matched by token, not by any "-" suffix, because Maven qualifiers like Guava's 33.0.0-jre are releases.
        return not _is_prerelease(parse_version_key(version))


def newest_first(versions: Iterable[Any]) -> list[str]:
    """The raw string breaks ties so a set-derived input orders the same every run."""
    return sorted((str(v) for v in versions), key=lambda v: (parse_version_key(v), v), reverse=True)


def split_fixed_versions(value: Any) -> list[str]:
    """The single versions of a stored fixed_version, which writers join with ", " per release line."""
    return [part for raw in str(value or "").split(",") if (part := raw.strip())]


def _upgrade_candidates(fixed_version: Any, installed_key: VersionKey) -> list[tuple[VersionKey, str]]:
    """A fix below the installed release is another line's backport."""
    candidates = [(key, part) for part in split_fixed_versions(fixed_version) if (key := parse_version_key(part))]
    return [(key, c) for key, c in candidates if key >= installed_key] or candidates


def _major_sort_key(major: int | str) -> tuple[bool, int, str]:
    return isinstance(major, str), major if isinstance(major, int) else 0, str(major)


def aggregate_fixed_version(entries: Iterable[Mapping[str, Any]], installed_version: str | None) -> str | None:
    installed_key = parse_version_key(installed_version or "")
    advisories = [_upgrade_candidates(entry.get("fixed_version"), installed_key) for entry in entries]
    by_major: dict[int | str, dict[int, list[tuple[VersionKey, str]]]] = {}
    for index, candidates in enumerate(advisories):
        for key, candidate in candidates:
            by_major.setdefault(key[0][1], {}).setdefault(index, []).append((key, candidate))
    # A prerelease fix counts only where the line offers no release fix.
    line_fixes = [
        (
            major,
            max(
                (min(fixes, key=lambda fix: (_is_prerelease(fix[0]), fix[0])) for fixes in per_advisory.values()),
                key=itemgetter(0),
            )[1],
        )
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
