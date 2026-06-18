"""
Findings-delta computation: matches findings across two scans by a
type-specific semantic key (CVE id, secret pattern hash, SAST rule id, …)
and produces the unified envelope.

The on-disk `severity` field is stored UPPERCASE (per the Severity enum);
the envelope lower-cases it and `_SEVERITY_RANK` keys are lowercase so
ordering works regardless of the caller's case.
"""

from __future__ import annotations

import hashlib
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.schemas.scan_delta import (
    DeltaCategory,
    FindingDeltaItem,
    ScanDeltaResponse,
    ScanDeltaTotals,
)
from app.services.analytics._delta_pagination import MAX_FETCH, paginate

_SEVERITY_RANK = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "negligible": 4,
    "info": 5,
    "unknown": 6,
}


def _first_id(details: Dict[str, Any], *keys: str) -> str:
    """Return the first truthy value among ``details[k]`` for the given keys,
    stringified. Empty when none of the keys carry a usable identifier."""
    for key in keys:
        value = details.get(key)
        if value:
            return str(value)
    return ""


def _sast_identifier(details: Dict[str, Any]) -> str:
    rule = _first_id(details, "rule_id")
    line = details.get("line")
    return f"{rule}:{line}" if line is not None else rule


# Each entry returns the type-specific identifier or "" when no stable id
# is present (callers fall back to the description+found_in hash).
_FINDING_TYPE_IDENTIFIER: Dict[str, Callable[[Dict[str, Any]], str]] = {
    "vulnerability": lambda d: _first_id(d, "cve_id", "vuln_id"),
    "secret": lambda d: _first_id(d, "pattern_hash", "rule_id"),
    "sast": _sast_identifier,
    "iac": lambda d: _first_id(d, "rule_id"),
    "license": lambda d: _first_id(d, "license_id", "license"),
    "malware": lambda d: _first_id(d, "signature", "rule_id"),
    "eol": lambda d: _first_id(d, "eol_date", "version"),
    "outdated": lambda d: _first_id(d, "latest_version"),
}


def _fallback_identifier(finding: Dict[str, Any]) -> str:
    """Deterministic hash of description + found_in so an unidentifiable
    finding at least matches itself across scans if those are stable."""
    digest_src = (finding.get("description") or "") + "|" + "|".join(finding.get("found_in") or [])
    # Non-cryptographic identity hash — collision resistance not required.
    return hashlib.sha1(digest_src.encode("utf-8"), usedforsecurity=False).hexdigest()[:12]


def finding_identity_key(finding: Dict[str, Any]) -> Tuple[str, str, str]:
    """Stable identity for matching the 'same' finding across two scans.

    finding_id is per-scan and unusable; we derive a semantic key from
    type-specific identifier fields, with a description-hash fallback for
    finding types that lack a stable identifier in their details dict.
    """
    ftype = finding.get("type") or ""
    component = finding.get("component") or ""
    details = finding.get("details") or {}

    extractor = _FINDING_TYPE_IDENTIFIER.get(ftype)
    identifier = extractor(details) if extractor else ""
    if not identifier:
        identifier = _fallback_identifier(finding)

    return (ftype, component, identifier)


async def _fetch_scan_findings(
    db: AsyncIOMotorDatabase,
    project_id: str,
    scan_id: str,
    finding_type: Optional[Iterable[str]],
    severity: Optional[Iterable[str]],
) -> List[dict]:
    query: dict = {"project_id": project_id, "scan_id": scan_id}
    if finding_type:
        query["type"] = {"$in": list(finding_type)}
    if severity:
        # Severity enum values are stored UPPERCASE; normalise the
        # (case-insensitive) caller input here so the $in matches.
        query["severity"] = {"$in": [s.upper() for s in severity]}
    cursor = db["findings"].find(query).limit(MAX_FETCH)
    return [doc async for doc in cursor]


def _to_item(doc: dict, change: str) -> FindingDeltaItem:
    details = doc.get("details") or {}
    found_in = doc.get("found_in") or []
    return FindingDeltaItem(
        change=change,
        finding_id=str(doc.get("finding_id") or doc.get("_id") or ""),
        finding_type=doc.get("type") or "",
        # Normalise to lowercase so the envelope is consistent regardless of
        # how the underlying storage cased the value.
        severity=(doc.get("severity") or "unknown").lower(),
        title=doc.get("description") or "",
        component=doc.get("component"),
        cve_id=details.get("cve_id"),
        file_path=(found_in[0] if found_in else None),
        first_seen=doc.get("created_at"),
    )


async def compute_findings_delta(
    db: AsyncIOMotorDatabase,
    *,
    project_id: str,
    from_scan: str,
    to_scan: str,
    page: int,
    page_size: int,
    change: Optional[str],
    severity: Optional[List[str]],
    finding_type: Optional[List[str]],
) -> ScanDeltaResponse:
    """Compute the delta between two scans' findings.

    Fetches findings for both scans (optionally filtered by type/severity),
    matches them via the semantic identity key, and produces an envelope
    summarising added/removed/unchanged counts plus a paginated item list.
    """
    from_docs = await _fetch_scan_findings(db, project_id, from_scan, finding_type, severity)
    to_docs = await _fetch_scan_findings(db, project_id, to_scan, finding_type, severity)

    from_map = {finding_identity_key(d): d for d in from_docs}
    to_map = {finding_identity_key(d): d for d in to_docs}

    added_keys = to_map.keys() - from_map.keys()
    removed_keys = from_map.keys() - to_map.keys()
    unchanged_count = len(to_map.keys() & from_map.keys())

    added_items = [_to_item(to_map[k], "added") for k in added_keys]
    removed_items = [_to_item(from_map[k], "removed") for k in removed_keys]

    # Breakdowns decompose the FULL added+removed populations so they always
    # reconcile with totals.added + totals.removed, independent of the `change`
    # filter that only scopes the paginated item list (audit #12).
    by_severity: Dict[str, int] = {}
    by_type: Dict[str, int] = {}
    for item in (*added_items, *removed_items):
        by_severity[item.severity] = by_severity.get(item.severity, 0) + 1
        by_type[item.finding_type] = by_type.get(item.finding_type, 0) + 1

    items: List[FindingDeltaItem] = []
    if change in (None, "all", "added"):
        items.extend(added_items)
    if change in (None, "all", "removed"):
        items.extend(removed_items)

    # Stable sort: added before removed, then by severity (critical first), then title,
    # then finding_id as a final tiebreaker so pagination is deterministic regardless
    # of set-iteration order.
    items.sort(
        key=lambda i: (
            i.change != "added",
            _SEVERITY_RANK.get(i.severity, 99),
            i.title,
            i.finding_id,
        )
    )

    paged, total_pages = paginate(items, page, page_size)

    return ScanDeltaResponse(
        from_scan_id=from_scan,
        to_scan_id=to_scan,
        project_id=project_id,
        category=DeltaCategory.FINDINGS,
        totals=ScanDeltaTotals(
            added=len(added_keys),
            removed=len(removed_keys),
            unchanged=unchanged_count,
            by_severity=by_severity,
            by_type=by_type,
        ),
        page=page,
        page_size=page_size,
        total_pages=total_pages,
        items=paged,
    )
