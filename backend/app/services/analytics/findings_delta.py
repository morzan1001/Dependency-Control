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


def _vulnerability_identifier(finding: Dict[str, Any]) -> str:
    """Identity for an aggregated vulnerability record.

    Persisted vulnerability findings are the AGGREGATED shape produced by
    ``ResultAggregator._add_vulnerability_finding``: the CVE/advisory ids live in
    ``details.vulnerabilities[].id`` (there is no flat ``details.cve_id``), and
    the affected package version is a top-level field. Key on the sorted id set
    plus the version so that adding/dropping a CVE, or bumping the version, is
    detected as a change instead of being reported "unchanged".
    """
    details = finding.get("details") or {}
    version = finding.get("version") or ""
    vulns = details.get("vulnerabilities") or []
    ids = sorted(str(v.get("id")) for v in vulns if isinstance(v, dict) and v.get("id"))
    if not ids:
        # Legacy / non-aggregated shape: fall back to flat id fields.
        legacy = _first_id(details, "cve_id", "vuln_id")
        ids = [legacy] if legacy else []
    if not ids:
        return ""
    joined = ",".join(ids)
    return f"{version}|{joined}" if version else joined


def _secret_identifier(finding: Dict[str, Any]) -> str:
    """Secrets have a deterministic, cross-scan-stable ``finding_id``
    (``SECRET-<detector>-<hash8>``) derived from the detector plus a hash of the
    secret value. Persisted secret findings carry no ``pattern_hash``/``rule_id``
    in details (only detector/decoder/verified/redacted), so key on the
    finding_id instead."""
    return str(finding.get("finding_id") or finding.get("_id") or "")


# Each entry returns the type-specific identifier or "" when no stable id
# is present (callers fall back to the description+found_in hash). These
# extractors read only the ``details`` dict.
_FINDING_TYPE_IDENTIFIER: Dict[str, Callable[[Dict[str, Any]], str]] = {
    "sast": _sast_identifier,
    "iac": lambda d: _first_id(d, "rule_id"),
    "license": lambda d: _first_id(d, "license_id", "license"),
    "malware": lambda d: _first_id(d, "signature", "rule_id"),
    "eol": lambda d: _first_id(d, "eol_date", "version"),
    "outdated": lambda d: _first_id(d, "fixed_version"),
}

# Extractors that need top-level finding fields (version, finding_id), not just
# the details dict.
_FINDING_TYPE_IDENTIFIER_FULL: Dict[str, Callable[[Dict[str, Any]], str]] = {
    "vulnerability": _vulnerability_identifier,
    "secret": _secret_identifier,
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

    full_extractor = _FINDING_TYPE_IDENTIFIER_FULL.get(ftype)
    if full_extractor:
        identifier = full_extractor(finding)
    else:
        extractor = _FINDING_TYPE_IDENTIFIER.get(ftype)
        identifier = extractor(details) if extractor else ""
    if not identifier:
        identifier = _fallback_identifier(finding)

    return (ftype, component, identifier)


# Projection covering exactly the fields consumed by finding_identity_key and
# _to_item. Stored vulnerability findings embed the full
# details.vulnerabilities[] payload (per-CVE descriptions, references,
# matched_rules and a nested copy of details), so two large scans can otherwise
# pull hundreds of MB into the worker per compare_scans call. Projecting to
# details.vulnerabilities.id keeps only the id of each entry. All keys are
# inclusions (plus the implicit _id), so this is a valid Mongo projection.
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
        # Severity enum values are stored UPPERCASE; normalise the
        # (case-insensitive) caller input here so the $in matches.
        query["severity"] = {"$in": [s.upper() for s in severity]}
    cursor = db["findings"].find(query, projection=_FETCH_PROJECTION).limit(MAX_FETCH)
    return [doc async for doc in cursor]


def _doc_severity(doc: dict) -> str:
    # Normalise to lowercase so the envelope is consistent regardless of casing.
    return (doc.get("severity") or "unknown").lower()


def _doc_type(doc: dict) -> str:
    return doc.get("type") or ""


def _item_cve_id(details: Dict[str, Any]) -> Optional[str]:
    """Best display CVE id for the item. Aggregated vulnerability findings keep
    their ids under ``details.vulnerabilities[].id``; only legacy/flat shapes
    carry ``details.cve_id``."""
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

    # Breakdowns decompose the FULL added+removed populations so they always
    # reconcile with totals.added + totals.removed, independent of the `change`
    # filter that only scopes the paginated item list (audit #12). Count straight
    # from the raw docs so we don't materialise up to MAX_FETCH Pydantic items just
    # to bump two counters (audit SC#9).
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

    # Build Pydantic items only for the change-filtered set that is actually returned.
    items: List[FindingDeltaItem] = []
    if change in (None, "all", "added"):
        items.extend(_to_item(to_map[k], "added") for k in added_keys)
    if change in (None, "all", "removed"):
        items.extend(_to_item(from_map[k], "removed") for k in removed_keys)

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
