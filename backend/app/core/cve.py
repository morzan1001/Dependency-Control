"""The CVE identity of a vulnerability advisory entry (one of a finding's details.vulnerabilities)."""

from collections.abc import Mapping
from typing import Any


def advisory_id(raw: Any) -> str | None:
    """An advisory id as its database spells it: upper case, a GHSA id's body lower case."""
    if not isinstance(raw, str) or not (ident := raw.strip().upper()):
        return None
    return f"GHSA-{ident.removeprefix('GHSA-').lower()}" if ident.startswith("GHSA-") else ident


def advisory_ids(entry: Mapping[str, Any]) -> set[str]:
    """Every id an advisory is known under: its id, its aliases and its resolved CVE."""
    return {i for i in (entry.get("id"), entry.get("resolved_cve"), *(entry.get("aliases") or [])) if i}


def advisory_match(value: Any, prefix: str = "details.vulnerabilities") -> dict[str, Any]:
    """Mongo clause for the advisories known under `value` (an id or an operator on one), as advisory_ids lists them."""
    return {"$or": [{f"{prefix}.{field}": value} for field in ("id", "aliases", "resolved_cve")]}


def entry_cves(entry: Mapping[str, Any]) -> list[str]:
    """Every CVE an advisory names, resolved_cve first, then its id, then its aliases."""
    ids = (advisory_id(i) for i in (entry.get("resolved_cve"), entry.get("id"), *(entry.get("aliases") or [])))
    return list(dict.fromkeys(i for i in ids if i and i.startswith("CVE-")))


def counted_cves(entry: Mapping[str, Any]) -> list[str]:
    """The ids an advisory is counted under: every CVE it names, or its own id when it names none."""
    ident = advisory_id(entry.get("id"))
    return entry_cves(entry) or ([ident] if ident else [])


def canonical_cve(entry: Mapping[str, Any]) -> str | None:
    """The one id an advisory is shown under (GHSA-only ecosystems keep their own id)."""
    return next(iter(counted_cves(entry)), None)


def canonical_cves(details_list: list[Any]) -> list[str]:
    """Distinct CVEs across advisory lists; an advisory bundling several CVEs counts each of them."""
    seen: dict[str, None] = {}
    for details in details_list:
        if not isinstance(details, dict):
            continue
        for entry in details.get("vulnerabilities") or []:
            if isinstance(entry, dict):
                seen.update(dict.fromkeys(counted_cves(entry)))
    return list(seen)


def display_vulnerability_id(details: Any) -> str | None:
    """The one id a vulnerability finding is shown under: its first advisory CVE, else its first advisory's id."""
    ids = canonical_cves([details])
    return next((i for i in ids if i.startswith("CVE-")), next(iter(ids), None))
