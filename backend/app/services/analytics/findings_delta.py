"""Findings-delta: match findings across two scans by a type-specific semantic key
(CVE id, secret finding_id, SAST rule id, ...) into the unified envelope.

Stored `severity` is UPPERCASE; the envelope and `_SEVERITY_RANK` keys are lowercase.
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


def _vulnerability_identifier(finding: Dict[str, Any]) -> str:
    """Identity for an aggregated vulnerability record.

    CVE/advisory ids live in ``details.vulnerabilities[].id`` and version is top-level;
    key on the sorted id set plus version so adding/dropping a CVE or a version bump reads
    as a change, not "unchanged".
    """
    details = finding.get("details") or {}
    version = finding.get("version") or ""
    vulns = details.get("vulnerabilities") or []
    ids = sorted(str(v.get("id")) for v in vulns if isinstance(v, dict) and v.get("id"))
    if not ids:
        # Fall back to flat id fields for the non-aggregated shape.
        legacy = _first_id(details, "cve_id", "vuln_id")
        ids = [legacy] if legacy else []
    if not ids:
        return ""
    joined = ",".join(ids)
    return f"{version}|{joined}" if version else joined


def _secret_identifier(finding: Dict[str, Any]) -> str:
    """Secrets carry a deterministic cross-scan-stable ``finding_id``, so key on it."""
    return str(finding.get("finding_id") or finding.get("_id") or "")


# Extractors reading only ``details``; return "" when no stable id is present.
_FINDING_TYPE_IDENTIFIER: Dict[str, Callable[[Dict[str, Any]], str]] = {
    "sast": _sast_identifier,
    "iac": lambda d: _first_id(d, "rule_id"),
    "license": lambda d: _first_id(d, "license_id", "license"),
    "malware": lambda d: _first_id(d, "signature", "rule_id"),
    "eol": lambda d: _first_id(d, "eol_date", "version"),
    "outdated": lambda d: _first_id(d, "fixed_version"),
}

# Extractors needing top-level finding fields (version, finding_id), not just details.
_FINDING_TYPE_IDENTIFIER_FULL: Dict[str, Callable[[Dict[str, Any]], str]] = {
    "vulnerability": _vulnerability_identifier,
    "secret": _secret_identifier,
}


def _fallback_identifier(finding: Dict[str, Any]) -> str:
    """Hash of description + found_in so an unidentifiable finding matches itself across scans."""
    digest_src = (finding.get("description") or "") + "|" + "|".join(finding.get("found_in") or [])
    return hashlib.sha1(digest_src.encode("utf-8"), usedforsecurity=False).hexdigest()[:12]


def finding_identity_key(finding: Dict[str, Any]) -> Tuple[str, str, str]:
    """Stable identity for matching the same finding across two scans (finding_id is per-scan)."""
    ftype = finding.get("type") or ""
    component = finding.get("component") or ""
    details = finding.get("details") or {}

    full_extractor = _FINDING_TYPE_IDENTIFIER_FULL.get(ftype)
    if full_extractor:
        identifier = full_extractor(finding)
    else:
        extractor = _FINDING_TYPE_IDENTIFIER.get(ftype)
        identifier = extractor(details) if extractor else ""
    if not identifier:
        identifier = _fallback_identifier(finding)

    return (ftype, component, identifier)


# Fields consumed by finding_identity_key and _to_item. Projecting
# details.vulnerabilities to .id avoids pulling the full per-CVE payload (hundreds of
# MB on large scans) into the worker. All keys are inclusions (valid Mongo projection).
_FETCH_PROJECTION: Dict[str, int] = {
    "type": 1,
    "component": 1,
    "version": 1,
    "severity": 1,
    "description": 1,
    "found_in": 1,
    "finding_id": 1,
    "created_at": 1,
    "details.vulnerabilities.id": 1,
    "details.cve_id": 1,
    "details.vuln_id": 1,
    "details.rule_id": 1,
    "details.line": 1,
    "details.license_id": 1,
    "details.license": 1,
    "details.signature": 1,
    "details.eol_date": 1,
    "details.fixed_version": 1,
}


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
        # Severity is stored UPPERCASE; normalise case-insensitive caller input for $in.
        query["severity"] = {"$in": [s.upper() for s in severity]}
    cursor = db["findings"].find(query, projection=_FETCH_PROJECTION).limit(MAX_FETCH)
    return [doc async for doc in cursor]


def _doc_severity(doc: dict) -> str:
    return (doc.get("severity") or "unknown").lower()


def _doc_type(doc: dict) -> str:
    return doc.get("type") or ""


def _item_cve_id(details: Dict[str, Any]) -> Optional[str]:
    """Best display CVE id: flat ``details.cve_id`` else first ``details.vulnerabilities[].id``."""
    cve = details.get("cve_id")
    if cve:
        return str(cve)
    for entry in details.get("vulnerabilities") or []:
        if isinstance(entry, dict) and entry.get("id"):
            return str(entry["id"])
    return None


def _to_item(doc: dict, change: str) -> FindingDeltaItem:
    details = doc.get("details") or {}
    found_in = doc.get("found_in") or []
    return FindingDeltaItem(
        change=change,
        finding_id=str(doc.get("finding_id") or doc.get("_id") or ""),
        finding_type=_doc_type(doc),
        severity=_doc_severity(doc),
        title=doc.get("description") or "",
        component=doc.get("component"),
        cve_id=_item_cve_id(details),
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
    """Compute the delta between two scans' findings as a paginated envelope."""
    from_docs = await _fetch_scan_findings(db, project_id, from_scan, finding_type, severity)
    to_docs = await _fetch_scan_findings(db, project_id, to_scan, finding_type, severity)

    from_map = {finding_identity_key(d): d for d in from_docs}
    to_map = {finding_identity_key(d): d for d in to_docs}

    added_keys = to_map.keys() - from_map.keys()
    removed_keys = from_map.keys() - to_map.keys()
    unchanged_count = len(to_map.keys() & from_map.keys())

    # Breakdowns cover the full added+removed populations so they reconcile with
    # totals.added + totals.removed, independent of the `change` filter that only scopes
    # the item list. Count from raw docs to avoid materialising MAX_FETCH Pydantic items.
    by_severity: Dict[str, int] = {}
    by_type: Dict[str, int] = {}
    for k in added_keys:
        doc = to_map[k]
        by_severity[_doc_severity(doc)] = by_severity.get(_doc_severity(doc), 0) + 1
        by_type[_doc_type(doc)] = by_type.get(_doc_type(doc), 0) + 1
    for k in removed_keys:
        doc = from_map[k]
        by_severity[_doc_severity(doc)] = by_severity.get(_doc_severity(doc), 0) + 1
        by_type[_doc_type(doc)] = by_type.get(_doc_type(doc), 0) + 1

    # Build Pydantic items only for the change-filtered set that is returned.
    items: List[FindingDeltaItem] = []
    if change in (None, "all", "added"):
        items.extend(_to_item(to_map[k], "added") for k in added_keys)
    if change in (None, "all", "removed"):
        items.extend(_to_item(from_map[k], "removed") for k in removed_keys)

    # Stable sort (added first, then severity, title, finding_id) for deterministic pagination.
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
