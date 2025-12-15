from fastapi import APIRouter, Depends, HTTPException
from motor.motor_asyncio import AsyncIOMotorDatabase, AsyncIOMotorGridFSBucket
from pymongo.errors import DocumentTooLarge
import logging
import json
from app.api import deps
from app.schemas.ingest import SBOMIngest
from app.schemas.trufflehog import TruffleHogIngest
from app.schemas.opengrep import OpenGrepIngest
from app.schemas.kics import KicsIngest
from app.schemas.bearer import BearerIngest
from app.models.project import Project, Scan
from app.db.mongodb import get_database
from app.core.worker import worker_manager
from app.services.aggregator import ResultAggregator
from datetime import datetime
import uuid

logger = logging.getLogger(__name__)

router = APIRouter()

@router.post("/ingest/trufflehog", summary="Ingest TruffleHog Results", status_code=200)
async def ingest_trufflehog(
    data: TruffleHogIngest,
    project: Project = Depends(deps.get_project_for_ingest),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """
    Ingest TruffleHog secret scan results.
    Returns a summary of findings and pipeline failure status.
    """
    # Extract metadata
    metadata = data.metadata.dict(by_alias=True)
    pipeline_id = data.metadata.ci_pipeline_id
    pipeline_iid = data.metadata.ci_pipeline_iid

    # 1. Find or Create Scan Record (Pipeline)
    existing_scan = None
    if pipeline_id:
        existing_scan = await db.scans.find_one({
            "project_id": str(project.id),
            "pipeline_id": pipeline_id
        })

    if existing_scan:
        scan_id = existing_scan["_id"]
        # Update metadata if needed
        await db.scans.update_one(
            {"_id": scan_id},
            {"$set": {"metadata": metadata, "updated_at": datetime.utcnow()}}
        )
    else:
        scan = Scan(
            project_id=str(project.id),
            branch=data.metadata.ci_commit_branch or data.branch or "unknown",
            commit_hash=data.commit_hash,
            pipeline_id=pipeline_id,
            pipeline_iid=pipeline_iid,
            metadata=metadata,
            status="processing",
            created_at=datetime.utcnow(),
            completed_at=datetime.utcnow()
        )
        await db.scans.insert_one(scan.dict(by_alias=True))
        scan_id = scan.id
    
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
    # We append results to allow multiple reports from the same tool (e.g. multiple jobs)
    await db.analysis_results.insert_one({
        "_id": str(uuid.uuid4()),
        "scan_id": scan_id,
        "analyzer_name": "trufflehog",
        "result": trufflehog_result,
        "created_at": datetime.utcnow()
    })
    
    # Update Scan with summary
    # We trigger aggregation via worker
    await worker_manager.add_job(scan_id)
    
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
    project: Project = Depends(deps.get_project_for_ingest),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """
    Upload an SBOM for analysis.
    
    Requires a valid **API Key** in the `X-API-Key` header or **GitLab OIDC Token**.
    The analysis will be queued and processed by background workers.
    """
    # Extract metadata
    metadata = data.metadata.dict(by_alias=True)
    pipeline_id = data.metadata.ci_pipeline_id
    pipeline_iid = data.metadata.ci_pipeline_iid
    
    # Prepare SBOMs list
    new_sboms = data.sboms
        
    if not new_sboms:
        raise HTTPException(status_code=400, detail="No SBOM provided")

    # Check for existing scan for this pipeline
    existing_scan = None
    if pipeline_id:
        existing_scan = await db.scans.find_one({
            "project_id": str(project.id),
            "pipeline_id": pipeline_id
        })
    
    try:
        if existing_scan:
            # Update existing scan
            scan_id = existing_scan["_id"]
            
            # Check for duplicates based on job_id if we tracked it, but for now just append
            # We could check if the exact same SBOM content is already there, but that's expensive.
            
            await db.scans.update_one(
                {"_id": scan_id},
                {
                    "$set": {
                        "metadata": metadata,
                        "branch": data.metadata.ci_commit_branch or data.branch or existing_scan.get("branch"),
                        "commit_hash": data.commit_hash or existing_scan.get("commit_hash"),
                        "status": "pending", # Reset status to pending to re-analyze with new data
                        "updated_at": datetime.utcnow()
                    },
                    "$push": {
                        "sboms": {"$each": new_sboms}
                    }
                }
            )
        else:
            # Create new scan
            scan = Scan(
                project_id=str(project.id),
                branch=data.metadata.ci_commit_branch or data.branch or "unknown",
                commit_hash=data.commit_hash,
                pipeline_id=pipeline_id,
                pipeline_iid=pipeline_iid,
                metadata=metadata,
                sboms=new_sboms,
                status="pending"
            )
            await db.scans.insert_one(scan.dict(by_alias=True))
            scan_id = scan.id
    except DocumentTooLarge:
        logger.warning(f"SBOM content too large for pipeline {pipeline_id}, attempting to offload to GridFS")
        try:
            # Initialize GridFS
            fs = AsyncIOMotorGridFSBucket(db)
            gridfs_sboms = []
            
            for sbom in new_sboms:
                sbom_str = json.dumps(sbom)
                sbom_bytes = sbom_str.encode('utf-8')
                file_id = await fs.upload_from_stream(
                    f"sbom-{uuid.uuid4()}.json",
                    sbom_bytes,
                    metadata={"contentType": "application/json"}
                )
                gridfs_sboms.append({"gridfs_id": str(file_id), "type": "gridfs_reference"})
            
            if existing_scan:
                scan_id = existing_scan["_id"]
                await db.scans.update_one(
                    {"_id": scan_id},
                    {
                        "$set": {
                            "metadata": metadata,
                            "branch": data.metadata.ci_commit_branch or data.branch or existing_scan.get("branch"),
                            "commit_hash": data.commit_hash or existing_scan.get("commit_hash"),
                            "status": "pending",
                            "updated_at": datetime.utcnow()
                        },
                        "$push": {
                            "sboms": {"$each": gridfs_sboms}
                        }
                    }
                )
            else:
                # Re-create scan object with GridFS references
                scan = Scan(
                    project_id=str(project.id),
                    branch=data.metadata.ci_commit_branch or data.branch or "unknown",
                    commit_hash=data.commit_hash,
                    pipeline_id=pipeline_id,
                    pipeline_iid=pipeline_iid,
                    metadata=metadata,
                    sboms=gridfs_sboms,
                    status="pending"
                )
                await db.scans.insert_one(scan.dict(by_alias=True))
                scan_id = scan.id
                
        except Exception as e2:
             logger.error(f"Error offloading SBOM to GridFS: {e2}", exc_info=True)
             raise HTTPException(status_code=413, detail="SBOM content is too large and failed to offload to GridFS.")
    except Exception as e:
        logger.error(f"Error ingesting SBOM for pipeline {pipeline_id}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Internal Server Error during ingestion: {str(e)}")
    
    # Add to Worker Queue
    await worker_manager.add_job(scan_id)
    
    return {"status": "queued", "scan_id": scan_id, "message": "Analysis queued successfully"}

@router.post("/ingest/opengrep", summary="Ingest OpenGrep Results", status_code=200)
async def ingest_opengrep(
    data: OpenGrepIngest,
    project: Project = Depends(deps.get_project_for_ingest),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """
    Ingest OpenGrep SAST scan results.
    Returns a summary of findings.
    """
    # Extract metadata
    metadata = data.metadata.dict(by_alias=True)
    pipeline_id = data.metadata.ci_pipeline_id
    pipeline_iid = data.metadata.ci_pipeline_iid

    # 1. Find or Create Scan Record (Pipeline)
    existing_scan = None
    if pipeline_id:
        existing_scan = await db.scans.find_one({
            "project_id": str(project.id),
            "pipeline_id": pipeline_id
        })

    if existing_scan:
        scan_id = existing_scan["_id"]
        # Update metadata if needed
        await db.scans.update_one(
            {"_id": scan_id},
            {"$set": {"metadata": metadata, "updated_at": datetime.utcnow()}}
        )
    else:
        scan = Scan(
            project_id=str(project.id),
            branch=data.metadata.ci_commit_branch or data.branch or "unknown",
            commit_hash=data.commit_hash,
            pipeline_id=pipeline_id,
            pipeline_iid=pipeline_iid,
            metadata=metadata,
            status="processing", # Mark as processing as we are adding results
            created_at=datetime.utcnow(),
            completed_at=datetime.utcnow()
        )
        await db.scans.insert_one(scan.dict(by_alias=True))
        scan_id = scan.id
    
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
    # We append results to allow multiple reports from the same tool
    await db.analysis_results.insert_one({
        "_id": str(uuid.uuid4()),
        "scan_id": scan_id,
        "analyzer_name": "opengrep",
        "result": opengrep_result,
        "created_at": datetime.utcnow()
    })
    
    # Update Scan with summary (This needs to be smarter to aggregate with other analyzers)
    # For now, we just trigger a re-calculation of the total stats if possible, 
    # or we just return the stats for THIS ingestion.
    # Ideally, we should have a background task that aggregates all AnalysisResults for a scan_id.
    # But for simplicity, let's just return the stats for this run.
    
    stats = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "unknown": 0}
    for f in final_findings:
        sev = f.get("severity", "UNKNOWN").lower()
        if sev in stats:
            stats[sev] += 1
        else:
            stats["unknown"] += 1
            
    # We don't overwrite scan.findings_summary here because it might contain other analyzers' data.
    # We should probably trigger an aggregation task.
    await worker_manager.add_job(scan_id) # Re-run aggregation
    
    # Update Project Stats
    await db.projects.update_one(
        {"_id": str(project.id)},
        {"$set": {"last_scan_at": datetime.utcnow()}}
    )
    
    return {
        "scan_id": scan_id,
        "findings_count": len(final_findings),
        "stats": stats
    }

@router.post("/ingest/kics", summary="Ingest KICS Results", status_code=200)
async def ingest_kics(
    data: KicsIngest,
    project: Project = Depends(deps.get_project_for_ingest),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """
    Ingest KICS IaC scan results.
    """
    # Extract metadata
    metadata = data.metadata.dict(by_alias=True)
    pipeline_id = data.metadata.ci_pipeline_id
    pipeline_iid = data.metadata.ci_pipeline_iid

    # 1. Find or Create Scan Record (Pipeline)
    existing_scan = None
    if pipeline_id:
        existing_scan = await db.scans.find_one({
            "project_id": str(project.id),
            "pipeline_id": pipeline_id
        })

    if existing_scan:
        scan_id = existing_scan["_id"]
        await db.scans.update_one(
            {"_id": scan_id},
            {"$set": {"metadata": metadata, "updated_at": datetime.utcnow()}}
        )
    else:
        scan = Scan(
            project_id=str(project.id),
            branch=data.metadata.ci_commit_branch or data.branch or "unknown",
            commit_hash=data.commit_hash,
            pipeline_id=pipeline_id,
            pipeline_iid=pipeline_iid,
            metadata=metadata,
            status="processing",
            created_at=datetime.utcnow(),
            completed_at=datetime.utcnow()
        )
        await db.scans.insert_one(scan.dict(by_alias=True))
        scan_id = scan.id
    
    aggregator = ResultAggregator()
    kics_result = data.dict()
    
    aggregator.aggregate("kics", kics_result)
    findings = aggregator.get_findings()
    
    # Apply Waivers
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

    # Store Results
    await db.analysis_results.insert_one({
        "_id": str(uuid.uuid4()),
        "scan_id": scan_id,
        "analyzer_name": "kics",
        "result": kics_result,
        "created_at": datetime.utcnow()
    })
    
    # Update Scan
    stats = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "unknown": 0}
    for f in final_findings:
        sev = f.get("severity", "UNKNOWN").lower()
        if sev in stats:
            stats[sev] += 1
        else:
            stats["unknown"] += 1
            
    await worker_manager.add_job(scan_id)
    
    await db.projects.update_one(
        {"_id": str(project.id)},
        {"$set": {"last_scan_at": datetime.utcnow()}}
    )
    
    return {
        "scan_id": scan_id,
        "findings_count": len(final_findings),
        "stats": stats
    }

@router.post("/ingest/bearer", summary="Ingest Bearer Results", status_code=200)
async def ingest_bearer(
    data: BearerIngest,
    project: Project = Depends(deps.get_project_for_ingest),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """
    Ingest Bearer SAST/Data Security scan results.
    """
    # Extract metadata
    metadata = data.metadata.dict(by_alias=True)
    pipeline_id = data.metadata.ci_pipeline_id
    pipeline_iid = data.metadata.ci_pipeline_iid

    # 1. Find or Create Scan Record (Pipeline)
    existing_scan = None
    if pipeline_id:
        existing_scan = await db.scans.find_one({
            "project_id": str(project.id),
            "pipeline_id": pipeline_id
        })

    if existing_scan:
        scan_id = existing_scan["_id"]
        await db.scans.update_one(
            {"_id": scan_id},
            {"$set": {"metadata": metadata, "updated_at": datetime.utcnow()}}
        )
    else:
        scan = Scan(
            project_id=str(project.id),
            branch=data.metadata.ci_commit_branch or data.branch or "unknown",
            commit_hash=data.commit_hash,
            pipeline_id=pipeline_id,
            pipeline_iid=pipeline_iid,
            metadata=metadata,
            status="processing",
            created_at=datetime.utcnow(),
            completed_at=datetime.utcnow()
        )
        await db.scans.insert_one(scan.dict(by_alias=True))
        scan_id = scan.id
    
    aggregator = ResultAggregator()
    bearer_result = data.dict()
    
    aggregator.aggregate("bearer", bearer_result)
    findings = aggregator.get_findings()
    
    # Apply Waivers
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

    # Store Results
    await db.analysis_results.insert_one({
        "_id": str(uuid.uuid4()),
        "scan_id": scan_id,
        "analyzer_name": "bearer",
        "result": bearer_result,
        "created_at": datetime.utcnow()
    })
    
    # Update Scan
    stats = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "unknown": 0}
    for f in final_findings:
        sev = f.get("severity", "UNKNOWN").lower()
        if sev in stats:
            stats[sev] += 1
        else:
            stats["unknown"] += 1
            
    await worker_manager.add_job(scan_id)
    
    await db.projects.update_one(
        {"_id": str(project.id)},
        {"$set": {"last_scan_at": datetime.utcnow()}}
    )
    
    return {
        "scan_id": scan_id,
        "findings_count": len(final_findings),
        "stats": stats
    }


@router.get("/ingest/config", summary="Get Project Configuration", status_code=200)
async def get_project_config(
    project: Project = Depends(deps.get_project_for_ingest),
):
    """
    Get project configuration for CI/CD pipelines.
    Returns active analyzers and other settings.
    """
    return {
        "active_analyzers": project.active_analyzers,
        "retention_days": project.retention_days
    }

