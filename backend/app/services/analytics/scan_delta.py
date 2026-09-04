"""
Orchestrator for the unified scan-delta endpoint.

Validates the public query parameters, then dispatches to the per-category
delta service. Service-layer functions trust pre-validated inputs; auth and
cross-project scan checks live one layer above (REST handler / MCP wrapper).
"""

from __future__ import annotations

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.core import ensure_utc
from app.models.finding import FindingType, Severity
from app.schemas.scan_delta import ScanDeltaResponse, ScanDeltaSide
from app.services.analytics.components_delta import compute_components_delta
from app.services.analytics.crypto_delta import compute_crypto_delta_envelope
from app.services.analytics.findings_delta import compute_findings_delta


class InvalidDeltaQuery(ValueError):
    """Raised when scan-delta query parameters are mutually inconsistent."""


# Severities accepted case-insensitively; the Severity enum stores UPPERCASE.
_VALID_SEVERITIES = {s.value.lower() for s in Severity}
_VALID_FINDING_TYPES = {t.value for t in FindingType}
_VALID_CHANGES_BY_CATEGORY = {
    "findings": {"added", "removed", "all"},
    "components": {"added", "removed", "changed", "all"},
    "crypto": {"added", "removed", "all"},
}
_MIN_PAGE = 1
_MIN_PAGE_SIZE = 1
_MAX_PAGE_SIZE = 200
_SIDE_PROJECTION = {"branch": 1, "commit_hash": 1, "created_at": 1}


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
) -> None:
    # A pair the server resolved onto one scan is a real question with an empty answer; a caller
    # naming the same id twice made a mistake.
    if from_scan == to_scan and not allow_same_scan:
        raise InvalidDeltaQuery("from_scan_id and to_scan_id must differ")
    if category not in _VALID_CHANGES_BY_CATEGORY:
        raise InvalidDeltaQuery(f"unknown category: {category}")
    if page < _MIN_PAGE:
        raise InvalidDeltaQuery(f"page must be >= {_MIN_PAGE}")
    if page_size < _MIN_PAGE_SIZE or page_size > _MAX_PAGE_SIZE:
        raise InvalidDeltaQuery(f"page_size must be between {_MIN_PAGE_SIZE} and {_MAX_PAGE_SIZE}")
    if category != "findings" and (severity or finding_type):
        raise InvalidDeltaQuery("severity and finding_type are only valid with category=findings")
    if severity:
        _reject_unknown(severity, _VALID_SEVERITIES, "severity", case_insensitive=True)
    if finding_type:
        _reject_unknown(finding_type, _VALID_FINDING_TYPES, "finding_type")
    if change is not None and change not in _VALID_CHANGES_BY_CATEGORY[category]:
        valid = ", ".join(sorted(_VALID_CHANGES_BY_CATEGORY[category]))
        raise InvalidDeltaQuery(f"change={change} is not valid for category={category} (valid: {valid})")


async def _describe_sides(
    db: AsyncIOMotorDatabase, from_scan: str, to_scan: str
) -> tuple[ScanDeltaSide, ScanDeltaSide]:
    """The build each side is, so a caller can check a symbolic side resolved to what it expected."""
    docs = {doc["_id"]: doc async for doc in db["scans"].find({"_id": {"$in": [from_scan, to_scan]}}, _SIDE_PROJECTION)}

    def _side(scan_id: str) -> ScanDeltaSide:
        doc = docs.get(scan_id) or {}
        return ScanDeltaSide(
            scan_id=scan_id,
            branch=doc.get("branch"),
            commit_hash=doc.get("commit_hash"),
            created_at=ensure_utc(doc.get("created_at")),
        )

    return _side(from_scan), _side(to_scan)


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
    _validate_query(
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

    if category == "findings":
        response = await compute_findings_delta(
            db,
            project_id=project_id,
            from_scan=from_scan,
            to_scan=to_scan,
            page=page,
            page_size=page_size,
            change=change,
            severity=severity,
            finding_type=finding_type,
        )
    elif category == "components":
        response = await compute_components_delta(
            db,
            project_id=project_id,
            from_scan=from_scan,
            to_scan=to_scan,
            page=page,
            page_size=page_size,
            change=change,
        )
    else:
        response = await compute_crypto_delta_envelope(
            db,
            project_id=project_id,
            from_scan=from_scan,
            to_scan=to_scan,
            page=page,
            page_size=page_size,
            change=change,
        )

    response.from_side, response.to_side = await _describe_sides(db, from_scan, to_scan)
    return response
