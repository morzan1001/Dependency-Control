"""Resolves which scans the inventory and findings-export views read from."""

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.models.project import Project, Scan
from app.repositories.scans import ScanRepository


async def active_branches(db: AsyncIOMotorDatabase, project: Project) -> list[str]:
    branches = await ScanRepository(db).distinct("branch", {"project_id": project.id})
    deleted = set(project.deleted_branches or [])
    return sorted(b for b in branches if b and b not in deleted)


async def latest_completed_scan(db: AsyncIOMotorDatabase, project_id: str, branch: str) -> Scan | None:
    data = await ScanRepository(db).find_one(
        {"project_id": project_id, "branch": branch, "status": "completed"},
        sort=[("created_at", -1)],
    )
    return Scan(**data) if data else None


async def latest_completed_scans_by_branch(db: AsyncIOMotorDatabase, project: Project) -> list[Scan]:
    scans: list[Scan] = []
    for branch in await active_branches(db, project):
        scan = await latest_completed_scan(db, project.id, branch)
        if scan:
            scans.append(scan)
    return scans


async def resolve_inventory_scan(
    db: AsyncIOMotorDatabase, project: Project, branch: str | None
) -> Scan | None:
    if branch:
        if branch in (project.deleted_branches or []):
            return None
        return await latest_completed_scan(db, project.id, branch)
    default = project.default_branch
    if default and default not in (project.deleted_branches or []):
        scan = await latest_completed_scan(db, project.id, default)
        if scan:
            return scan
    return await ScanRepository(db).get_latest_active_scan(project)
