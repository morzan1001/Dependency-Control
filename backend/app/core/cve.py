from collections.abc import Mapping
from typing import Any


def advisory_id(raw: Any) -> str | None:
    """An advisory id as its database spells it: upper case, a GHSA id's body lower case."""
    if not isinstance(raw, str) or not (ident := raw.strip().upper()):
        return None
    return f"GHSA-{ident.removeprefix('GHSA-').lower()}" if ident.startswith("GHSA-") else ident


def advisory_ids(entry: Mapping[str, Any]) -> set[str]:
    return {i for i in (entry.get("id"), entry.get("resolved_cve"), *(entry.get("aliases") or [])) if i}


ADVISORY_ID_FIELDS = ("id", "aliases", "resolved_cve")


def advisory_match(value: Any, prefix: str = "details.vulnerabilities") -> dict[str, Any]:
    """Mongo clause for the advisories known under `value` (an id or an operator on one), as advisory_ids lists them."""
    return {"$or": [{f"{prefix}.{field}": value} for field in ADVISORY_ID_FIELDS]}


def entry_cves(entry: Mapping[str, Any]) -> list[str]:
    ids = (advisory_id(i) for i in (entry.get("resolved_cve"), entry.get("id"), *(entry.get("aliases") or [])))
    return list(dict.fromkeys(i for i in ids if i and i.startswith("CVE-")))


def counted_cves(entry: Mapping[str, Any]) -> list[str]:
    ident = advisory_id(entry.get("id"))
    return entry_cves(entry) or ([ident] if ident else [])


def counted_cves_expr(entry: str) -> dict[str, Any]:
    """counted_cves as an aggregation expression, upper-cased: two ids match exactly when their advisory_id does."""

    def ident(value: str) -> dict[str, Any]:
        return {"$cond": [{"$eq": [{"$type": value}, "string"]}, {"$toUpper": {"$trim": {"input": value}}}, ""]}

    listed = {"$concatArrays": [[f"{entry}.resolved_cve", f"{entry}.id"], {"$ifNull": [f"{entry}.aliases", []]}]}
    ids = {"$map": {"input": listed, "as": "i", "in": ident("$$i")}}
    cves = {"$setUnion": [{"$filter": {"input": ids, "cond": {"$eq": [{"$substrCP": ["$$this", 0, 4]}, "CVE-"]}}}]}
    own = {"$filter": {"input": [ident(f"{entry}.id")], "cond": {"$ne": ["$$this", ""]}}}
    return {"$let": {"vars": {"cves": cves}, "in": {"$cond": [{"$eq": ["$$cves", []]}, own, "$$cves"]}}}


def canonical_cve(entry: Mapping[str, Any]) -> str | None:
    """An advisory naming no CVE, as in GHSA-only ecosystems, is shown under its own id."""
    return next(iter(counted_cves(entry)), None)


def canonical_cves(details_list: list[Any]) -> list[str]:
    seen: dict[str, None] = {}
    for details in details_list:
        if not isinstance(details, dict):
            continue
        for entry in details.get("vulnerabilities") or []:
            if isinstance(entry, dict):
                seen.update(dict.fromkeys(counted_cves(entry)))
    return list(seen)
