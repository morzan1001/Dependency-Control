from fastapi import HTTPException

from app.api.deps import DatabaseDep
from app.models.project import Project
from app.repositories.scans import ScanRepository

SCAN_NOT_IN_PROJECT = "No scan found for this project"


async def resolve_project_scan_id(db: DatabaseDep, project: Project, scan_id: str | None) -> str | None:
    scan_repo = ScanRepository(db)
    if scan_id is None:
        return await scan_repo.get_latest_active_scan_id(project)
    if not await scan_repo.belongs_to_project({scan_id}, project.id):
        raise HTTPException(status_code=404, detail=SCAN_NOT_IN_PROJECT)
    return scan_id
