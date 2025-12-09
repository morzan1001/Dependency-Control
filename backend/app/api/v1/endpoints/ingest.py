from fastapi import APIRouter, Depends, BackgroundTasks, HTTPException
from motor.motor_asyncio import AsyncIOMotorDatabase
from app.api import deps
from app.schemas.ingest import SBOMIngest
from app.schemas.trufflehog import TruffleHogIngest
from app.schemas.opengrep import OpenGrepIngest
from app.models.project import Project, Scan, AnalysisResult
from app.db.mongodb import get_database
from app.core.worker import worker_manager
from app.services.aggregator import ResultAggregator
from datetime import datetime
import uuid

router = APIRouter()

@router.post("/ingest/trufflehog", summary="Ingest TruffleHog Results", status_code=200)
async def ingest_trufflehog(
    data: TruffleHogIngest,
    project: Project = Depends(deps.get_project_by_api_key),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """
    Ingest TruffleHog secret scan results.
    Returns a summary of findings and pipeline failure status.
    """
    # 1. Create or Update Scan
    # Attempts to find a pending scan for this commit, or create a new one.
    # Since this is a specific "secret scan", a new completed scan entry is created
    # to store the results history.
    
    scan = Scan(
        project_id=str(project.id),
        branch=data.branch,
        commit_hash=data.commit_hash,
        sbom=None, # Secret scan doesn't have SBOM
        status="completed", # Processed immediately
        created_at=datetime.utcnow(),
        completed_at=datetime.utcnow()
    )
    
    # 2. Normalize Findings
    aggregator = ResultAggregator()
    # Convert Pydantic models to dicts
    trufflehog_result = {"findings": [f.dict() for f in data.findings]}
    
    aggregator.aggregate("trufflehog", trufflehog_result)
    findings = aggregator.get_findings()
    
    # 3. Apply Waivers
    # Fetch active waivers for this project
    waivers_cursor = db.waivers.find({
        "$or": [
            {"project_id": str(project.id)},
            {"project_id": None} # Global waivers
        ],
        "expiration_date": {"$gt": datetime.utcnow()}
    })
    waivers = await waivers_cursor.to_list(length=1000)
    
    final_findings = []
    waived_count = 0
    
    for finding in findings:
        is_waived = False
        for waiver in waivers:
            # Check if waiver matches finding
            # Match by ID (e.g. SECRET-AWS-...)
            if waiver.get("finding_id") and waiver["finding_id"] == finding["id"]:
                is_waived = True
                break
            
            # Match by Type (e.g. "secret")
            if waiver.get("finding_type") and waiver["finding_type"] == finding["type"]:
                # Broad matching supported
                is_waived = True
                break
                
            # Match by Package Name (mapped to file path for secrets)
            if waiver.get("package_name") and waiver["package_name"] == finding["component"]:
                is_waived = True
                break
        
        if is_waived:
            waived_count += 1
            # It can be optionally stored but marked as waived
            finding["waived"] = True
        else:
            final_findings.append(finding)

    # 4. Store Results
    # Store raw result
    await db.analysis_results.insert_one({
        "_id": str(uuid.uuid4()),
        "scan_id": scan.id,
        "analyzer_name": "trufflehog",
        "result": trufflehog_result,
        "created_at": datetime.utcnow()
    })
    
    # Update Scan with summary
    stats = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "unknown": 0}
    for f in final_findings:
        severity = f.get("severity", "UNKNOWN").lower()
        if severity in stats:
            stats[severity] += 1
            
    scan.findings_summary = final_findings
    scan.findings_count = len(final_findings)
    scan.stats = stats
    
    await db.scans.insert_one(scan.dict(by_alias=True))
    
    # 5. Return Status
    # Fail if any critical findings remain
    failed = len(final_findings) > 0
    
    return {
        "status": "failed" if failed else "success",
        "scan_id": scan.id,
        "findings_count": len(final_findings),
        "waived_count": waived_count,
        "message": f"Found {len(final_findings)} secrets (Waived: {waived_count})"
    }

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

@router.post("/ingest/opengrep", summary="Ingest OpenGrep Results", status_code=200)
async def ingest_opengrep(
    data: OpenGrepIngest,
    project: Project = Depends(deps.get_project_by_api_key),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """
    Ingest OpenGrep SAST scan results.
    Returns a summary of findings.
    """
    # 1. Create Scan Record
    scan = Scan(
        project_id=str(project.id),
        branch=data.branch,
        commit_hash=data.commit_hash,
        sbom=None,
        status="completed",
        created_at=datetime.utcnow(),
        completed_at=datetime.utcnow()
    )
    
    # 2. Normalize Findings
    aggregator = ResultAggregator()
    opengrep_result = {"findings": [f.dict() for f in data.findings]}
    
    aggregator.aggregate("opengrep", opengrep_result)
    findings = aggregator.get_findings()
    
    # 3. Apply Waivers
    waivers_cursor = db.waivers.find({
        "$or": [
            {"project_id": str(project.id)},
            {"project_id": None}
        ],
        "expiration_date": {"$gt": datetime.utcnow()}
    })
    waivers = await waivers_cursor.to_list(length=1000)
    
    final_findings = []
    
    for finding in findings:
        is_waived = False
        for waiver in waivers:
            if waiver.get("finding_id") and waiver["finding_id"] == finding["id"]:
                is_waived = True
                break
            if waiver.get("finding_type") and waiver["finding_type"] == finding["type"]:
                is_waived = True
                break
            if waiver.get("package_name") and waiver["package_name"] == finding["component"]:
                is_waived = True
                break
        
        if is_waived:
            finding["waived"] = True
        else:
            final_findings.append(finding)

    # 4. Store Results
    await db.analysis_results.insert_one({
        "_id": str(uuid.uuid4()),
        "scan_id": scan.id,
        "analyzer_name": "opengrep",
        "result": opengrep_result,
        "created_at": datetime.utcnow()
    })
    
    # Update Scan with summary
    stats = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "unknown": 0}
    for f in final_findings:
        sev = f.get("severity", "UNKNOWN").lower()
        if sev in stats:
            stats[sev] += 1
        else:
            stats["unknown"] += 1
            
    scan.findings_summary = final_findings
    scan.findings_count = len(final_findings)
    scan.stats = stats
    
    await db.scans.insert_one(scan.dict(by_alias=True))
    
    # Update Project Stats
    await db.projects.update_one(
        {"_id": str(project.id)},
        {"$set": {"last_scan_at": datetime.utcnow()}}
    )
    
    return {
        "scan_id": scan.id,
        "findings_count": len(final_findings),
        "stats": stats
    }

