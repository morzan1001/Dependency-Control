from fastapi import APIRouter, Depends, BackgroundTasks
from motor.motor_asyncio import AsyncIOMotorDatabase
from app.api import deps
from app.schemas.ingest import SBOMIngest
from app.models.project import Project, Scan
from app.services.analysis import run_analysis
from app.db.mongodb import get_database

router = APIRouter()

@router.post("/ingest", summary="Ingest SBOM", status_code=202)
async def ingest_sbom(
    data: SBOMIngest,
    background_tasks: BackgroundTasks,
    project: Project = Depends(deps.get_project_by_api_key),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """
    Upload an SBOM for analysis.
    
    Requires a valid **API Key** in the `X-API-Key` header.
    The analysis will run in the background.
    """
    # Create Scan record
    scan = Scan(
        project_id=str(project.id),
        branch=data.branch,
        commit_hash=data.commit_hash,
        sbom=data.sbom
    )
    result = await db.scans.insert_one(scan.dict(by_alias=True))
    scan_id = scan.id
    
    # Trigger Analysis Workers
    background_tasks.add_task(
        run_analysis, 
        scan_id, 
        data.sbom, 
        project.active_analyzers, 
        db
    )
    
    return {"status": "accepted", "scan_id": scan_id}
