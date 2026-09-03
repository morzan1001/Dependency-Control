"""
Orchestrator for the unified scan-delta endpoint.

Validates the public query parameters, then dispatches to the per-category
delta service. Service-layer functions trust pre-validated inputs; auth and
cross-project scan checks live one layer above (REST handler / MCP wrapper).
"""

from __future__ import annotations

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.models.finding import FindingType, Severity
from app.schemas.scan_delta import ScanDeltaReachability, ScanDeltaResponse
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
_REACHABILITY_PATH = "stats.reachability"
_UNREPORTED_COUNT = 0


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


async def _side_reachability(db: AsyncIOMotorDatabase, scan_id: str) -> ScanDeltaReachability | None:
    """Coverage of one side, or None when that scan reports no reachability at all."""
    doc = await db["scans"].find_one({"_id": scan_id}, {_REACHABILITY_PATH: 1})
    reach = ((doc or {}).get("stats") or {}).get("reachability")
    if not reach:
        return None
    return ScanDeltaReachability(
        coverable_count=reach.get("coverable_count", _UNREPORTED_COUNT),
        analyzed_count=reach.get("analyzed_count", _UNREPORTED_COUNT),
    )


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

    # Every category is scored against the same reachability, so every category has to carry the
    # label; without it a reachability-empty side reads as comparable to an enriched one.
    response.from_reachability = await _side_reachability(db, from_scan)
    response.to_reachability = await _side_reachability(db, to_scan)
    return response
