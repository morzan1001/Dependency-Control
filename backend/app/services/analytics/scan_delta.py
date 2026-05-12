from __future__ import annotations

from typing import List, Optional

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.schemas.scan_delta import ScanDeltaResponse
from app.services.analytics.components_delta import compute_components_delta
from app.services.analytics.crypto_delta import compute_crypto_delta_envelope
from app.services.analytics.findings_delta import compute_findings_delta


class InvalidDeltaQuery(ValueError):
    """Raised when scan-delta query parameters are mutually inconsistent."""


_VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}
_VALID_FINDING_TYPES = {
    "vulnerability",
    "license",
    "secret",
    "malware",
    "eol",
    "iac",
    "sast",
    "quality",
    "outdated",
    "other",
}
_VALID_CHANGES_BY_CATEGORY = {
    "findings": {"added", "removed", "all"},
    "components": {"added", "removed", "changed", "all"},
    "crypto": {"added", "removed", "all"},
}
_MIN_PAGE = 1
_MIN_PAGE_SIZE = 1
_MAX_PAGE_SIZE = 200


def _reject_unknown(values: List[str], allowed: set, label: str) -> None:
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
    change: Optional[str],
    severity: Optional[List[str]],
    finding_type: Optional[List[str]],
) -> None:
    if from_scan == to_scan:
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
        _reject_unknown(severity, _VALID_SEVERITIES, "severity")
    if finding_type:
        _reject_unknown(finding_type, _VALID_FINDING_TYPES, "finding_type")
    if change is not None and change not in _VALID_CHANGES_BY_CATEGORY[category]:
        valid = ", ".join(sorted(_VALID_CHANGES_BY_CATEGORY[category]))
        raise InvalidDeltaQuery(f"change={change} is not valid for category={category} (valid: {valid})")


async def compute_scan_delta_dispatch(
    *,
    db: AsyncIOMotorDatabase,
    project_id: str,
    category: str,
    from_scan: str,
    to_scan: str,
    page: int,
    page_size: int,
    change: Optional[str],
    severity: Optional[List[str]],
    finding_type: Optional[List[str]],
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
    )

    if category == "findings":
        return await compute_findings_delta(
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
    if category == "components":
        return await compute_components_delta(
            db,
            project_id=project_id,
            from_scan=from_scan,
            to_scan=to_scan,
            page=page,
            page_size=page_size,
            change=change,
        )
    return await compute_crypto_delta_envelope(
        db,
        project_id=project_id,
        from_scan=from_scan,
        to_scan=to_scan,
        page=page,
        page_size=page_size,
        change=change,
    )
