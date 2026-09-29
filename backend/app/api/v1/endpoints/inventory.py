"""Per-project inventory endpoints: stats, components, licenses, crypto — JSON and CSV."""

from typing import Annotated

from fastapi import Depends, HTTPException, Query
from fastapi.responses import StreamingResponse

from app.api.deps import CurrentUserDep, DatabaseDep
from app.api.router import CustomAPIRouter
from app.api.v1.helpers.projects import check_project_access
from app.api.v1.helpers.responses import RESP_AUTH_404
from app.models.project import Project, Scan
from app.schemas.inventory import (
    ComponentsPageResponse,
    CryptoPageResponse,
    InventoryStatsResponse,
    LicensesResponse,
)
from app.services.inventory.components import (
    COMPONENT_COLUMNS,
    get_components_page,
    iter_component_rows,
)
from app.services.inventory.crypto import (
    CRYPTO_COLUMNS,
    get_crypto_page,
    iter_crypto_rows,
)
from app.services.inventory.csv_stream import csv_response, export_filename
from app.services.inventory.licenses import (
    LICENSE_COLUMNS,
    build_license_rows,
    iter_license_rows,
)
from app.services.inventory.scan_resolution import resolve_inventory_scan
from app.services.inventory.stats import build_inventory_stats, scan_context

router = CustomAPIRouter(tags=["inventory"])


async def _inventory_scope(
    project_id: str, current_user: CurrentUserDep, db: DatabaseDep, branch: str | None = Query(None)
) -> tuple[Project, Scan]:
    """The project the caller may view and the scan of the requested branch it reads."""
    project = await check_project_access(project_id, current_user, db)
    scan = await resolve_inventory_scan(db, project, branch)
    if scan is None:
        target = branch or project.default_branch or "any active branch"
        raise HTTPException(status_code=404, detail=f"No completed scan found for branch '{target}'")
    return project, scan


InventoryScopeDep = Annotated[tuple[Project, Scan], Depends(_inventory_scope)]


@router.get("/projects/{project_id}/inventory/stats", responses=RESP_AUTH_404)
async def inventory_stats(
    scope: InventoryScopeDep,
    db: DatabaseDep,
) -> InventoryStatsResponse:
    project, scan = scope
    return await build_inventory_stats(db, project, scan)


@router.get("/projects/{project_id}/inventory/components", responses=RESP_AUTH_404)
async def inventory_components(
    scope: InventoryScopeDep,
    db: DatabaseDep,
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=200),
    search: str | None = Query(None),
    sort_by: str = Query("name"),
    sort_order: str = Query("asc"),
) -> ComponentsPageResponse:
    _, scan = scope
    items, total = await get_components_page(
        db, scan, page=page, page_size=page_size, search=search, sort_by=sort_by, sort_order=sort_order
    )
    return ComponentsPageResponse(scan=scan_context(scan), items=items, total=total, page=page, page_size=page_size)


@router.get("/projects/{project_id}/inventory/components/export", responses=RESP_AUTH_404)
async def inventory_components_export(
    scope: InventoryScopeDep,
    db: DatabaseDep,
) -> StreamingResponse:
    project, scan = scope
    filename = export_filename(project.name, "components", scan.branch)
    return csv_response(filename, COMPONENT_COLUMNS, iter_component_rows(db, scan))


@router.get("/projects/{project_id}/inventory/licenses", responses=RESP_AUTH_404)
async def inventory_licenses(
    scope: InventoryScopeDep,
    db: DatabaseDep,
) -> LicensesResponse:
    _, scan = scope
    return LicensesResponse(scan=scan_context(scan), items=await build_license_rows(db, scan))


@router.get("/projects/{project_id}/inventory/licenses/export", responses=RESP_AUTH_404)
async def inventory_licenses_export(
    scope: InventoryScopeDep,
    db: DatabaseDep,
) -> StreamingResponse:
    project, scan = scope
    filename = export_filename(project.name, "licenses", scan.branch)
    return csv_response(filename, LICENSE_COLUMNS, iter_license_rows(db, scan))


@router.get("/projects/{project_id}/inventory/crypto", responses=RESP_AUTH_404)
async def inventory_crypto(
    scope: InventoryScopeDep,
    db: DatabaseDep,
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=200),
    search: str | None = Query(None),
) -> CryptoPageResponse:
    project, scan = scope
    items, total = await get_crypto_page(db, project.id, scan.id, page=page, page_size=page_size, search=search)
    return CryptoPageResponse(scan=scan_context(scan), items=items, total=total, page=page, page_size=page_size)


@router.get("/projects/{project_id}/inventory/crypto/export", responses=RESP_AUTH_404)
async def inventory_crypto_export(
    scope: InventoryScopeDep,
    db: DatabaseDep,
) -> StreamingResponse:
    project, scan = scope
    filename = export_filename(project.name, "crypto", scan.branch)
    return csv_response(filename, CRYPTO_COLUMNS, iter_crypto_rows(db, project.id, scan.id))
