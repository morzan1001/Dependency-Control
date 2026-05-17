"""
REST endpoint for the unified scan-delta API.

GET /api/v1/analytics/scan-delta dispatches across findings, components, and
crypto categories via ``compute_scan_delta_dispatch`` and returns a uniform
``ScanDeltaResponse`` envelope.

Notes
-----
* ``category`` is typed as ``str`` (not the ``DeltaCategory`` enum) so that
  invalid values surface as HTTP 400 through ``InvalidDeltaQuery`` instead of
  FastAPI's automatic 422. This keeps a single consistent error path through
  the orchestrator.
* Project authorization runs first; the cross-project scan guard runs after
  so the endpoint does not leak scan existence to non-members.
"""

from typing import List, Optional

from fastapi import HTTPException, Query

from app.api.deps import CurrentUserDep, DatabaseDep
from app.api.router import CustomAPIRouter
from app.api.v1.helpers.responses import RESP_400_403
from app.schemas.scan_delta import ScanDeltaResponse
from app.services.analytics.scan_delta import (
    InvalidDeltaQuery,
    compute_scan_delta_dispatch,
)
from app.services.analytics.scopes import ScopeResolutionError, ScopeResolver

router = CustomAPIRouter()


def _csv_to_list(value: Optional[str]) -> Optional[List[str]]:
    if not value:
        return None
    return [v.strip() for v in value.split(",") if v.strip()]


@router.get("/scan-delta", response_model=ScanDeltaResponse, responses=RESP_400_403)
async def get_scan_delta(
    current_user: CurrentUserDep,
    db: DatabaseDep,
    project_id: str = Query(...),
    from_scan_id: str = Query(...),
    to_scan_id: str = Query(...),
    category: str = Query(...),
    page: int = Query(1),
    page_size: int = Query(50),
    change: Optional[str] = Query(None),
    severity: Optional[str] = Query(None, description="csv: critical,high,medium,low"),
    finding_type: Optional[str] = Query(None, description="csv finding types"),
) -> ScanDeltaResponse:
    # 1. Project-level authorization (403 on non-membership).
    try:
        await ScopeResolver(db, current_user).resolve(
            scope="project",
            scope_id=project_id,
        )
    except ScopeResolutionError as e:
        raise HTTPException(status_code=403, detail=str(e))

    # 2. Cross-project scan guard — both scans MUST belong to project_id.
    #    Runs AFTER auth to avoid leaking scan existence to non-members.
    #    Skip when from==to (orchestrator will 400 that with a clearer message).
    if from_scan_id != to_scan_id:
        found = await db["scans"].count_documents(
            {"_id": {"$in": [from_scan_id, to_scan_id]}, "project_id": project_id},
        )
        if found != 2:
            raise HTTPException(status_code=400, detail="scan not in project")

    # 3. Dispatch — also validates category, change, and filter combinations.
    try:
        return await compute_scan_delta_dispatch(
            db=db,
            project_id=project_id,
            category=category,
            from_scan=from_scan_id,
            to_scan=to_scan_id,
            page=page,
            page_size=page_size,
            change=change,
            severity=_csv_to_list(severity),
            finding_type=_csv_to_list(finding_type),
        )
    except InvalidDeltaQuery as e:
        raise HTTPException(status_code=400, detail=str(e))
