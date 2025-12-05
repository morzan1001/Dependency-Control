from fastapi import APIRouter, Depends, BackgroundTasks
from motor.motor_asyncio import AsyncIOMotorDatabase
from app.api import deps
from app.schemas.ingest import SBOMIngest
from app.models.project import Project, Scan
from app.db.mongodb import get_database
from app.core.worker import worker_manager

router = APIRouter()

@router.post("/ingest", summary="Ingest SBOM", status_code=202)
async def ingest_sbom(
    data: SBOMIngest,
    project: Project = Depends(deps.get_project_by_api_key),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """
    Upload an SBOM for analysis.
    
    Requires a valid **API Key** in the `X-API-Key` header.
    The analysis will be queued and processed by background workers.
    """
    # Create Scan record
    scan = Scan(
        project_id=str(project.id),
        branch=data.branch,
        commit_hash=data.commit_hash,
        sbom=data.sbom,
        status="pending" # Explicitly set status to pending
    )
    result = await db.scans.insert_one(scan.dict(by_alias=True))
    scan_id = scan.id
    
    # Add to Worker Queue
    await worker_manager.add_job(scan_id)
    
    return {"status": "queued", "scan_id": scan_id, "message": "Analysis queued successfully"}

