from __future__ import annotations

import hashlib
from typing import Any, Dict, Iterable, List, Optional, Tuple

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.schemas.scan_delta import (
    DeltaCategory,
    FindingDeltaItem,
    ScanDeltaResponse,
    ScanDeltaTotals,
)

_MAX_FETCH = 50_000


def finding_identity_key(finding: Dict[str, Any]) -> Tuple[str, str, str]:
    """Stable identity for matching the 'same' finding across two scans.

    finding_id is per-scan and unusable; we derive a semantic key from
    type-specific identifier fields.
    """
    ftype = finding.get("type") or ""
    component = finding.get("component") or ""
    details = finding.get("details") or {}
    identifier: str

    if ftype == "vulnerability":
        identifier = str(details.get("cve_id") or details.get("vuln_id") or "")
    elif ftype == "secret":
        identifier = str(details.get("pattern_hash") or details.get("rule_id") or "")
    elif ftype == "sast":
        rule = str(details.get("rule_id") or "")
        line = details.get("line")
        identifier = f"{rule}:{line}" if line is not None else rule
    elif ftype == "iac":
        identifier = str(details.get("rule_id") or "")
    elif ftype == "license":
        identifier = str(details.get("license_id") or details.get("license") or "")
    elif ftype == "malware":
        identifier = str(details.get("signature") or details.get("rule_id") or "")
    elif ftype == "eol":
        identifier = str(details.get("eol_date") or details.get("version") or "")
    elif ftype == "outdated":
        identifier = str(details.get("latest_version") or "")
    else:
        identifier = ""

    if not identifier:
        # Fallback: deterministic hash of description + file_path so
        # an unidentifiable finding at least matches itself across scans
        # if its description/location is identical.
        digest_src = (
            (finding.get("description") or "")
            + "|"
            + "|".join(finding.get("found_in") or [])
        )
        identifier = hashlib.sha1(digest_src.encode("utf-8")).hexdigest()[:12]

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
        query["severity"] = {"$in": list(severity)}
    cursor = db["findings"].find(query).limit(_MAX_FETCH)
    return [doc async for doc in cursor]


def _to_item(doc: dict, change: str) -> FindingDeltaItem:
    details = doc.get("details") or {}
    found_in = doc.get("found_in") or []
    return FindingDeltaItem(
        change=change,
        finding_id=str(doc.get("finding_id") or doc.get("_id") or ""),
        finding_type=doc.get("type") or "",
        severity=doc.get("severity") or "unknown",
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

    items: List[FindingDeltaItem] = []
    if change in (None, "all", "added"):
        items.extend(_to_item(to_map[k], "added") for k in added_keys)
    if change in (None, "all", "removed"):
        items.extend(_to_item(from_map[k], "removed") for k in removed_keys)

    by_severity: Dict[str, int] = {}
    by_type: Dict[str, int] = {}
    for item in items:
        by_severity[item.severity] = by_severity.get(item.severity, 0) + 1
        by_type[item.finding_type] = by_type.get(item.finding_type, 0) + 1

    # Stable sort: added before removed, then by severity (critical first), then title
    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    items.sort(key=lambda i: (i.change != "added", severity_rank.get(i.severity, 99), i.title))

    total_items = len(items)
    total_pages = max(1, (total_items + page_size - 1) // page_size)
    start = (page - 1) * page_size
    end = start + page_size
    paged = items[start:end]

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
