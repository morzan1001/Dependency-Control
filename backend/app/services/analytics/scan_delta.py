from __future__ import annotations

from typing import List, Optional

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.schemas.scan_delta import ScanDeltaResponse
from app.services.analytics.components_delta import compute_components_delta
from app.services.analytics.crypto_delta import compute_crypto_delta_envelope
from app.services.analytics.findings_delta import compute_findings_delta


class InvalidDeltaQuery(ValueError):
    """Raised when scan-delta query parameters are mutually inconsistent."""


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
    if from_scan == to_scan:
        raise InvalidDeltaQuery("from_scan_id and to_scan_id must differ")
    if category not in {"findings", "components", "crypto"}:
        raise InvalidDeltaQuery(f"unknown category: {category}")
    if category != "findings" and (severity or finding_type):
        raise InvalidDeltaQuery(
            "severity and finding_type are only valid with category=findings"
        )
    if change == "changed" and category != "components":
        raise InvalidDeltaQuery(
            "change=changed is only valid with category=components"
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
