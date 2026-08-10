"""Per-project inventory endpoints: stats, components, licenses, crypto — JSON and CSV."""

from fastapi import HTTPException, Query
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.api.deps import CurrentUserDep, DatabaseDep
from app.api.router import CustomAPIRouter
from app.api.v1.helpers.projects import check_project_access
from app.api.v1.helpers.responses import RESP_AUTH_404
from app.models.project import Project, Scan
from app.schemas.inventory import InventoryStatsResponse
from app.services.inventory.scan_resolution import resolve_inventory_scan
from app.services.inventory.stats import build_inventory_stats

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
