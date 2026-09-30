"""Orchestrator for the unified scan-delta endpoint.

Service-layer functions trust pre-validated inputs; auth and cross-project scan
checks live one layer above (REST handler / chat tool registry).
"""

from __future__ import annotations

import asyncio
from typing import Any

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.models.finding import FindingType, Severity
from app.schemas.scan_delta import (
    DeltaCategory,
    ScanDeltaReachability,
    ScanDeltaResponse,
    ScanDeltaSide,
    ScanDeltaTotals,
)
from app.services.analytics._delta_pagination import page_of
from app.services.analytics.cache import get_analytics_cache
from app.services.analytics.components_delta import compare_components
from app.services.analytics.crypto_delta import compare_crypto
from app.services.analytics.findings_delta import compare_findings


class InvalidDeltaQuery(ValueError):
    """Raised when scan-delta query parameters are mutually inconsistent."""


# Severities accepted case-insensitively; the Severity enum stores UPPERCASE.
_VALID_SEVERITIES = {s.value.lower() for s in Severity}
_VALID_FINDING_TYPES = {t.value for t in FindingType}
_VALID_CHANGES = {"added", "removed", "changed", "all"}
_MIN_PAGE = 1
_MIN_PAGE_SIZE = 1
_MAX_PAGE_SIZE = 200
_SIDE_PROJECTION = {"branch": 1, "commit_hash": 1, "created_at": 1, "stats.reachability": 1}


def _reject_unknown(
    values: list[str],
    allowed: set,
    label: str,
    *,
    case_insensitive: bool = False,
) -> None:
    """Raise if any value is outside ``allowed``, echoing user-typed casing in the error."""
    if case_insensitive:
        unknown = [v for v in values if v.lower() not in allowed]
    else:
        unknown = [v for v in values if v not in allowed]
    if unknown:
        raise InvalidDeltaQuery(f"unknown {label} values: {', '.join(unknown)} (valid: {', '.join(sorted(allowed))})")


def _validate_query(
    *,
    category: str,
    from_scan: str,
    to_scan: str,
    page: int,
    page_size: int,
    change: str | None,
    severity: list[str] | None,
    finding_type: list[str] | None,
    allow_same_scan: bool,
) -> DeltaCategory:
    # A pair the server resolved onto one scan is a real question with an empty answer; a caller
    # naming the same id twice made a mistake.
    if from_scan == to_scan and not allow_same_scan:
        raise InvalidDeltaQuery("from_scan_id and to_scan_id must differ")
    try:
        cat = DeltaCategory(category)
    except ValueError:
        raise InvalidDeltaQuery(f"unknown category: {category}") from None
    if page < _MIN_PAGE:
        raise InvalidDeltaQuery(f"page must be >= {_MIN_PAGE}")
    if page_size < _MIN_PAGE_SIZE or page_size > _MAX_PAGE_SIZE:
        raise InvalidDeltaQuery(f"page_size must be between {_MIN_PAGE_SIZE} and {_MAX_PAGE_SIZE}")
    if cat is not DeltaCategory.FINDINGS and (severity or finding_type):
        raise InvalidDeltaQuery("severity and finding_type are only valid with category=findings")
    if severity:
        _reject_unknown(severity, _VALID_SEVERITIES, "severity", case_insensitive=True)
    if finding_type:
        _reject_unknown(finding_type, _VALID_FINDING_TYPES, "finding_type")
    if change is not None:
        _reject_unknown([change], _VALID_CHANGES, "change")
    return cat


async def _describe_sides(db: AsyncIOMotorDatabase, from_scan: str, to_scan: str) -> dict[str, Any]:
    """Each side's build and the reachability it was scored with, as envelope fields, so a caller can
    check a symbolic side resolved to what it expected."""
    docs = {doc["_id"]: doc async for doc in db["scans"].find({"_id": {"$in": [from_scan, to_scan]}}, _SIDE_PROJECTION)}
    fields: dict[str, Any] = {}
    for side, scan_id in (("from", from_scan), ("to", to_scan)):
        doc = docs.get(scan_id) or {}
        reach = (doc.get("stats") or {}).get("reachability")
        fields[f"{side}_side"] = ScanDeltaSide(
            scan_id=scan_id,
            branch=doc.get("branch"),
            commit_hash=doc.get("commit_hash"),
            created_at=doc.get("created_at"),
        )
        fields[f"{side}_reachability"] = (
            ScanDeltaReachability(
                coverable_count=reach.get("coverable_count", 0), analyzed_count=reach.get("analyzed_count", 0)
            )
            if reach
            else None
        )
    return fields


async def compute_scan_delta_dispatch(
    *,
    db: AsyncIOMotorDatabase,
    project_id: str,
    category: str,
    from_scan: str,
    to_scan: str,
    page: int,
    page_size: int,
    change: str | None,
    severity: list[str] | None,
    finding_type: list[str] | None,
    allow_same_scan: bool,
) -> ScanDeltaResponse:
    cat = _validate_query(
        category=category,
        from_scan=from_scan,
        to_scan=to_scan,
        page=page,
        page_size=page_size,
        change=change,
        severity=severity,
        finding_type=finding_type,
        allow_same_scan=allow_same_scan,
    )
    if from_scan == to_scan:
        side = ScanDeltaSide(scan_id=from_scan)
        return ScanDeltaResponse(
            from_scan_id=from_scan,
            to_scan_id=to_scan,
            project_id=project_id,
            category=cat,
            totals=ScanDeltaTotals(),
            page=page,
            page_size=page_size,
            from_side=side,
            to_side=side,
        )

    compare = {
        DeltaCategory.FINDINGS: lambda: compare_findings(
            db,
            project_id=project_id,
            from_scan=from_scan,
            to_scan=to_scan,
            severity=severity,
            finding_type=finding_type,
        ),
        DeltaCategory.COMPONENTS: lambda: compare_components(
            db, project_id=project_id, from_scan=from_scan, to_scan=to_scan
        ),
        DeltaCategory.CRYPTO: lambda: compare_crypto(db, project_id=project_id, from_scan=from_scan, to_scan=to_scan),
    }[cat]
    # `change` and the page only slice the comparison, so they stay out of the key.
    key = (
        "scan_delta",
        cat,
        project_id,
        from_scan,
        to_scan,
        tuple(sorted({s.upper() for s in severity or ()})),
        tuple(sorted(set(finding_type or ()))),
    )
    comparison, sides = await asyncio.gather(
        get_analytics_cache().get_or_compute(key, compare), _describe_sides(db, from_scan, to_scan)
    )
    return page_of(comparison, change, page, page_size).model_copy(update=sides)
