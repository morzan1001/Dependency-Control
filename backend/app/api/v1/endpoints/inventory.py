"""Per-project inventory endpoints: stats, components, licenses, crypto — JSON and CSV."""

from fastapi import HTTPException, Query
from fastapi.responses import StreamingResponse
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.api.deps import CurrentUserDep, DatabaseDep
from app.api.router import CustomAPIRouter
from app.api.v1.helpers.projects import check_project_access
from app.api.v1.helpers.responses import RESP_AUTH_404
from app.models.project import Project, Scan
from app.schemas.inventory import ComponentsPageResponse, InventoryStatsResponse
from app.services.inventory.components import (
    COMPONENT_COLUMNS,
    get_components_page,
    iter_component_rows,
)
from app.services.inventory.csv_stream import csv_response, export_filename
from app.services.inventory.scan_resolution import resolve_inventory_scan
from app.services.inventory.stats import build_inventory_stats, scan_context

router = CustomAPIRouter(tags=["inventory"])


async def _resolve_scan_or_404(db: AsyncIOMotorDatabase, project: Project, branch: str | None) -> Scan:
    scan = await resolve_inventory_scan(db, project, branch)
    if scan is None:
        target = branch or project.default_branch or "any active branch"
        raise HTTPException(status_code=404, detail=f"No completed scan found for branch '{target}'")
    return scan


@router.get("/projects/{project_id}/inventory/stats", responses=RESP_AUTH_404)
async def inventory_stats(
    project_id: str,
    current_user: CurrentUserDep,
    db: DatabaseDep,
    branch: str | None = Query(None),
) -> InventoryStatsResponse:
    project = await check_project_access(project_id, current_user, db, required_role="viewer")
    scan = await _resolve_scan_or_404(db, project, branch)
    return await build_inventory_stats(db, project, scan)


@router.get("/projects/{project_id}/inventory/components", responses=RESP_AUTH_404)
async def inventory_components(
    project_id: str,
    current_user: CurrentUserDep,
    db: DatabaseDep,
    branch: str | None = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=200),
    search: str | None = Query(None),
    sort_by: str = Query("name"),
    sort_order: str = Query("asc"),
) -> ComponentsPageResponse:
    project = await check_project_access(project_id, current_user, db, required_role="viewer")
    scan = await _resolve_scan_or_404(db, project, branch)
    items, total = await get_components_page(
        db, scan, page=page, page_size=page_size, search=search, sort_by=sort_by, sort_order=sort_order
    )
    return ComponentsPageResponse(
        scan=scan_context(scan), items=items, total=total, page=page, page_size=page_size
    )


@router.get("/projects/{project_id}/inventory/components/export", responses=RESP_AUTH_404)
async def inventory_components_export(
    project_id: str,
    current_user: CurrentUserDep,
    db: DatabaseDep,
    branch: str | None = Query(None),
) -> StreamingResponse:
    project = await check_project_access(project_id, current_user, db, required_role="viewer")
    scan = await _resolve_scan_or_404(db, project, branch)
    filename = export_filename(project.name, "components", scan.branch)
    return csv_response(filename, COMPONENT_COLUMNS, iter_component_rows(db, scan))
