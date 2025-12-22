import json
import logging
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from motor.motor_asyncio import AsyncIOMotorDatabase, AsyncIOMotorGridFSBucket
from pymongo.errors import DocumentTooLarge

from app.api import deps
from app.core.worker import worker_manager
from app.db.mongodb import get_database
from app.models.dependency import Dependency
from app.models.project import Project, Scan
from app.models.stats import Stats
from app.schemas.bearer import BearerIngest
from app.schemas.ingest import SBOMIngest
from app.schemas.kics import KicsIngest
from app.schemas.opengrep import OpenGrepIngest
from app.schemas.trufflehog import TruffleHogIngest
from app.services.aggregator import ResultAggregator
from app.services.sbom_parser import SBOMFormat, parse_sbom

logger = logging.getLogger(__name__)

router = APIRouter()


@router.post("/ingest/trufflehog", summary="Ingest TruffleHog Results", status_code=200)
async def ingest_trufflehog(
    data: TruffleHogIngest,
    project: Project = Depends(deps.get_project_for_ingest),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    Ingest TruffleHog secret scan results.
    Returns a summary of findings and pipeline failure status.
    """
    # Extract metadata
    pipeline_id = data.pipeline_id
    pipeline_iid = data.pipeline_iid

    # Construct Pipeline URL if missing
    pipeline_url = data.pipeline_url
    if not pipeline_url and data.project_url and pipeline_id:
        pipeline_url = f"{data.project_url}/-/pipelines/{pipeline_id}"

    # 1. Find or Create Scan Record (Pipeline)
    existing_scan = None
    if pipeline_id:
        existing_scan = await db.scans.find_one(
            {"project_id": str(project.id), "pipeline_id": pipeline_id}
        )

    if existing_scan:
        scan_id = existing_scan["_id"]
        # Update metadata if needed
        await db.scans.update_one(
            {"_id": scan_id},
            {
                "$set": {
                    "updated_at": datetime.now(timezone.utc),
                    "branch": data.branch or existing_scan.get("branch"),
                    "commit_hash": data.commit_hash or existing_scan.get("commit_hash"),
                    "project_url": data.project_url,
                    "pipeline_url": pipeline_url,
                    "job_id": data.job_id,
                    "job_started_at": data.job_started_at,
                    "project_name": data.project_name,
                    "commit_message": data.commit_message,
                    "commit_tag": data.commit_tag,
                    "pipeline_user": data.pipeline_user,
                    "status": "pending",  # Force pending to trigger re-aggregation
                }
            },
        )
    else:
        scan = Scan(
            project_id=str(project.id),
            branch=data.branch or "unknown",
            commit_hash=data.commit_hash,
            pipeline_id=pipeline_id,
            pipeline_iid=pipeline_iid,
            project_url=data.project_url,
            pipeline_url=pipeline_url,
            job_id=data.job_id,
            job_started_at=data.job_started_at,
            project_name=data.project_name,
            commit_message=data.commit_message,
            commit_tag=data.commit_tag,
            pipeline_user=data.pipeline_user,
            status="pending",
            created_at=datetime.now(timezone.utc),
        )
        await db.scans.insert_one(scan.model_dump(by_alias=True))
        scan_id = scan.id

    # 2. Normalize Findings
    aggregator = ResultAggregator()
    # Convert Pydantic models to dicts
    trufflehog_result = {"findings": [f.model_dump() for f in data.findings]}

    aggregator.aggregate("trufflehog", trufflehog_result)
    findings = aggregator.get_findings()

    # 3. Apply Waivers
    # Fetch active waivers for this project
    waivers_cursor = db.waivers.find(
        {
            "$or": [
                {"project_id": str(project.id)},
                {"project_id": None},  # Global waivers
            ],
            "expiration_date": {"$gt": datetime.now(timezone.utc)},
        }
    )
    waivers = await waivers_cursor.to_list(length=1000)

    final_findings = []
    waived_count = 0

    for finding in findings:
        is_waived = False
        for waiver in waivers:
            # Check if waiver matches finding
            # Match by ID (e.g. SECRET-AWS-...)
            if waiver.get("finding_id") and waiver["finding_id"] == finding.id:
                is_waived = True
                break

            # Match by Type (e.g. "secret")
            if waiver.get("finding_type") and waiver["finding_type"] == finding.type:
                # Broad matching supported
                is_waived = True
                break

            # Match by Package Name (mapped to file path for secrets)
            if (
                waiver.get("package_name")
                and waiver["package_name"] == finding.component
            ):
                is_waived = True
                break

        if is_waived:
            waived_count += 1
            # It can be optionally stored but marked as waived
            finding.waived = True
        else:
            final_findings.append(finding)

    # 4. Store Results
    # We append results to allow multiple reports from the same tool (e.g. multiple jobs)
    await db.analysis_results.insert_one(
        {
            "_id": str(uuid.uuid4()),
            "scan_id": scan_id,
            "analyzer_name": "trufflehog",
            "result": trufflehog_result,
            "created_at": datetime.now(timezone.utc),
        }
    )

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
        "message": f"Found {len(final_findings)} secrets (Waived: {waived_count})",
    }


@router.post("/ingest", summary="Ingest SBOM", status_code=202)
async def ingest_sbom(
    data: SBOMIngest,
    project: Project = Depends(deps.get_project_for_ingest),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    Upload an SBOM for analysis.

    Requires a valid **API Key** in the `X-API-Key` header or **GitLab OIDC Token**.
    The analysis will be queued and processed by background workers.
    """
    # Extract metadata
    pipeline_id = data.pipeline_id
    pipeline_iid = data.pipeline_iid

    # Construct Pipeline URL if missing
    pipeline_url = data.pipeline_url
    if not pipeline_url and data.project_url and pipeline_id:
        pipeline_url = f"{data.project_url}/-/pipelines/{pipeline_id}"

    # Prepare SBOMs list
    new_sboms = data.sboms

    if not new_sboms:
        raise HTTPException(status_code=400, detail="No SBOM provided")

    # Check for existing scan for this pipeline
    existing_scan = None
    if pipeline_id:
        existing_scan = await db.scans.find_one(
            {"project_id": str(project.id), "pipeline_id": pipeline_id}
        )

    # Initialize GridFS
    fs = AsyncIOMotorGridFSBucket(db)
    sbom_refs = []
    dependencies_to_insert = []

    # Determine scan_id (either existing or new)
    scan_id = existing_scan["_id"] if existing_scan else str(uuid.uuid4())

    for sbom in new_sboms:
        # 1. Upload to GridFS (Always)
        try:
            sbom_str = json.dumps(sbom)
            sbom_bytes = sbom_str.encode("utf-8")
            file_id = await fs.upload_from_stream(
                f"sbom-{uuid.uuid4()}.json",
                sbom_bytes,
                metadata={"contentType": "application/json", "scan_id": scan_id},
            )
            sbom_refs.append(
                {
                    "storage": "gridfs",
                    "file_id": str(file_id),
                    "filename": f"sbom-{uuid.uuid4()}.json",
                    "type": "gridfs_reference",  # Keep for compatibility with analysis.py
                    "gridfs_id": str(
                        file_id
                    ),  # Keep for compatibility with analysis.py
                }
            )
        except Exception as e:
            logger.error(f"Failed to upload SBOM to GridFS: {e}")
            continue

        # 2. Extract Dependencies for Indexing using unified parser
        try:
            parsed_sbom = parse_sbom(sbom)

            logger.info(
                f"Parsed SBOM: format={parsed_sbom.format.value}, "
                f"total={parsed_sbom.total_components}, "
                f"parsed={parsed_sbom.parsed_components}, "
                f"skipped={parsed_sbom.skipped_components}"
            )

            for parsed_dep in parsed_sbom.dependencies:
                dep = Dependency(
                    project_id=str(project.id),
                    scan_id=scan_id,
                    # Core Identity
                    name=parsed_dep.name,
                    version=parsed_dep.version,
                    purl=parsed_dep.purl,
                    type=parsed_dep.type,
                    # Licensing
                    license=parsed_dep.license,
                    license_url=parsed_dep.license_url,
                    # Scope and relationships
                    scope=parsed_dep.scope,
                    direct=parsed_dep.direct,
                    parent_components=parsed_dep.parent_components,
                    # Source/Origin info
                    source_type=parsed_dep.source_type,
                    source_target=parsed_dep.source_target,
                    layer_digest=parsed_dep.layer_digest,
                    found_by=parsed_dep.found_by,
                    locations=parsed_dep.locations,
                    # Security identifiers
                    cpes=parsed_dep.cpes,
                    # Package metadata
                    description=parsed_dep.description,
                    author=parsed_dep.author,
                    publisher=parsed_dep.publisher,
                    group=parsed_dep.group,
                    # External references
                    homepage=parsed_dep.homepage,
                    repository_url=parsed_dep.repository_url,
                    download_url=parsed_dep.download_url,
                    # Checksums
                    hashes=parsed_dep.hashes,
                    # Additional properties
                    properties=parsed_dep.properties,
                )
                dependencies_to_insert.append(dep.dict(by_alias=True))

        except Exception as e:
            logger.error(
                f"Failed to extract dependencies from SBOM: {e}", exc_info=True
            )

    # Bulk insert dependencies
    if dependencies_to_insert:
        try:
            # Optional: Delete old dependencies for this scan if it's a re-run
            if existing_scan:
                await db.dependencies.delete_many({"scan_id": scan_id})

            await db.dependencies.insert_many(dependencies_to_insert)
        except Exception as e:
            logger.error(f"Failed to insert dependencies: {e}")

    if existing_scan:
        # Update existing scan
        await db.scans.update_one(
            {"_id": scan_id},
            {
                "$set": {
                    "branch": data.branch or existing_scan.get("branch"),
                    "commit_hash": data.commit_hash or existing_scan.get("commit_hash"),
                    "project_url": data.project_url,
                    "pipeline_url": pipeline_url,
                    "job_id": data.job_id,
                    "job_started_at": data.job_started_at,
                    "project_name": data.project_name,
                    "commit_message": data.commit_message,
                    "commit_tag": data.commit_tag,
                    "pipeline_user": data.pipeline_user,
                    "status": "pending",  # Reset status to pending to re-analyze with new data
                    "updated_at": datetime.now(timezone.utc),
                },
                "$push": {"sbom_refs": {"$each": sbom_refs}},
            },
        )
    else:
        # Create new scan
        scan = Scan(
            id=scan_id,
            project_id=str(project.id),
            branch=data.branch or "unknown",
            commit_hash=data.commit_hash,
            pipeline_id=pipeline_id,
            pipeline_iid=pipeline_iid,
            project_url=data.project_url,
            pipeline_url=pipeline_url,
            job_id=data.job_id,
            job_started_at=data.job_started_at,
            project_name=data.project_name,
            commit_message=data.commit_message,
            commit_tag=data.commit_tag,
            pipeline_user=data.pipeline_user,
            sbom_refs=sbom_refs,
            status="pending",
        )
        await db.scans.insert_one(scan.dict(by_alias=True))

    # Add to Worker Queue
    await worker_manager.add_job(scan_id)

    return {
        "status": "queued",
        "scan_id": scan_id,
        "message": "Analysis queued successfully",
    }


@router.post("/ingest/opengrep", summary="Ingest OpenGrep Results", status_code=200)
async def ingest_opengrep(
    data: OpenGrepIngest,
    project: Project = Depends(deps.get_project_for_ingest),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    Ingest OpenGrep SAST scan results.
    Returns a summary of findings.
    """
    # Extract metadata
    pipeline_id = data.pipeline_id
    pipeline_iid = data.pipeline_iid

    # Construct Pipeline URL if missing
    pipeline_url = data.pipeline_url
    if not pipeline_url and data.project_url and pipeline_id:
        pipeline_url = f"{data.project_url}/-/pipelines/{pipeline_id}"

    # 1. Find or Create Scan Record (Pipeline)
    existing_scan = None
    if pipeline_id:
        existing_scan = await db.scans.find_one(
            {"project_id": str(project.id), "pipeline_id": pipeline_id}
        )

    if existing_scan:
        scan_id = existing_scan["_id"]
        # Update metadata if needed
        await db.scans.update_one(
            {"_id": scan_id},
            {
                "$set": {
                    "updated_at": datetime.now(timezone.utc),
                    "branch": data.branch or existing_scan.get("branch"),
                    "commit_hash": data.commit_hash or existing_scan.get("commit_hash"),
                    "project_url": data.project_url,
                    "pipeline_url": pipeline_url,
                    "job_id": data.job_id,
                    "job_started_at": data.job_started_at,
                    "project_name": data.project_name,
                    "commit_message": data.commit_message,
                    "commit_tag": data.commit_tag,
                    "pipeline_user": data.pipeline_user,
                    "status": "pending",  # Force pending to trigger re-aggregation
                }
            },
        )
    else:
        scan = Scan(
            project_id=str(project.id),
            branch=data.branch or "unknown",
            commit_hash=data.commit_hash,
            pipeline_id=pipeline_id,
            pipeline_iid=pipeline_iid,
            project_url=data.project_url,
            pipeline_url=pipeline_url,
            job_id=data.job_id,
            job_started_at=data.job_started_at,
            project_name=data.project_name,
            commit_message=data.commit_message,
            commit_tag=data.commit_tag,
            pipeline_user=data.pipeline_user,
            status="pending",  # Mark as pending to trigger aggregation
            created_at=datetime.now(timezone.utc),
        )
        await db.scans.insert_one(scan.model_dump(by_alias=True))
        scan_id = scan.id

    # 2. Normalize Findings
    aggregator = ResultAggregator()
    opengrep_result = {"findings": [f.model_dump() for f in data.findings]}

    aggregator.aggregate("opengrep", opengrep_result)
    findings = aggregator.get_findings()

    # 3. Apply Waivers
    waivers_cursor = db.waivers.find(
        {
            "$or": [{"project_id": str(project.id)}, {"project_id": None}],
            "expiration_date": {"$gt": datetime.now(timezone.utc)},
        }
    )
    waivers = await waivers_cursor.to_list(length=1000)

    final_findings = []

    for finding in findings:
        is_waived = False
        for waiver in waivers:
            if waiver.get("finding_id") and waiver["finding_id"] == finding.id:
                is_waived = True
                break
            if waiver.get("finding_type") and waiver["finding_type"] == finding.type:
                is_waived = True
                break
            if (
                waiver.get("package_name")
                and waiver["package_name"] == finding.component
            ):
                is_waived = True
                break

        if is_waived:
            finding.waived = True
        else:
            final_findings.append(finding)

    # 4. Store Results
    # We append results to allow multiple reports from the same tool
    await db.analysis_results.insert_one(
        {
            "_id": str(uuid.uuid4()),
            "scan_id": scan_id,
            "analyzer_name": "opengrep",
            "result": opengrep_result,
            "created_at": datetime.now(timezone.utc),
        }
    )

    # Update Scan with summary (This needs to be smarter to aggregate with other analyzers)
    # For now, we just trigger a re-calculation of the total stats if possible,
    # or we just return the stats for THIS ingestion.
    # Ideally, we should have a background task that aggregates all AnalysisResults for a scan_id.
    # But for simplicity, let's just return the stats for this run.

    stats = Stats()
    for f in final_findings:
        sev = f.severity.lower()
        if sev == "critical":
            stats.critical += 1
        elif sev == "high":
            stats.high += 1
        elif sev == "medium":
            stats.medium += 1
        elif sev == "low":
            stats.low += 1
        elif sev == "info":
            stats.info += 1
        else:
            stats.unknown += 1

    # We don't overwrite scan.findings_summary here because it might contain other analyzers' data.
    # We should probably trigger an aggregation task.
    await worker_manager.add_job(scan_id)  # Re-run aggregation

    # Update Project Stats
    await db.projects.update_one(
        {"_id": str(project.id)}, {"$set": {"last_scan_at": datetime.now(timezone.utc)}}
    )

    return {
        "scan_id": scan_id,
        "findings_count": len(final_findings),
        "stats": stats.model_dump(),
    }


@router.post("/ingest/kics", summary="Ingest KICS Results", status_code=200)
async def ingest_kics(
    data: KicsIngest,
    project: Project = Depends(deps.get_project_for_ingest),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    Ingest KICS IaC scan results.
    """
    # Extract metadata
    pipeline_id = data.pipeline_id
    pipeline_iid = data.pipeline_iid

    # Construct Pipeline URL if missing
    pipeline_url = data.pipeline_url
    if not pipeline_url and data.project_url and pipeline_id:
        pipeline_url = f"{data.project_url}/-/pipelines/{pipeline_id}"

    # 1. Find or Create Scan Record (Pipeline)
    existing_scan = None
    if pipeline_id:
        existing_scan = await db.scans.find_one(
            {"project_id": str(project.id), "pipeline_id": pipeline_id}
        )

    if existing_scan:
        scan_id = existing_scan["_id"]
        await db.scans.update_one(
            {"_id": scan_id},
            {
                "$set": {
                    "updated_at": datetime.now(timezone.utc),
                    "branch": data.branch or existing_scan.get("branch"),
                    "commit_hash": data.commit_hash or existing_scan.get("commit_hash"),
                    "project_url": data.project_url,
                    "pipeline_url": pipeline_url,
                    "job_id": data.job_id,
                    "job_started_at": data.job_started_at,
                    "project_name": data.project_name,
                    "commit_message": data.commit_message,
                    "commit_tag": data.commit_tag,
                    "pipeline_user": data.pipeline_user,
                    "status": "pending",  # Force pending to trigger re-aggregation
                }
            },
        )
    else:
        scan = Scan(
            project_id=str(project.id),
            branch=data.branch or "unknown",
            commit_hash=data.commit_hash,
            pipeline_id=pipeline_id,
            pipeline_iid=pipeline_iid,
            project_url=data.project_url,
            pipeline_url=pipeline_url,
            job_id=data.job_id,
            job_started_at=data.job_started_at,
            project_name=data.project_name,
            commit_message=data.commit_message,
            commit_tag=data.commit_tag,
            pipeline_user=data.pipeline_user,
            status="pending",
            created_at=datetime.now(timezone.utc),
        )
        await db.scans.insert_one(scan.model_dump(by_alias=True))
        scan_id = scan.id

    aggregator = ResultAggregator()
    kics_result = data.model_dump()

    aggregator.aggregate("kics", kics_result)
    findings = aggregator.get_findings()

    # Apply Waivers
    waivers_cursor = db.waivers.find(
        {
            "$or": [{"project_id": str(project.id)}, {"project_id": None}],
            "expiration_date": {"$gt": datetime.now(timezone.utc)},
        }
    )
    waivers = await waivers_cursor.to_list(length=1000)

    final_findings = []

    for finding in findings:
        is_waived = False
        for waiver in waivers:
            if waiver.get("finding_id") and waiver["finding_id"] == finding.id:
                is_waived = True
                break
            if waiver.get("finding_type") and waiver["finding_type"] == finding.type:
                is_waived = True
                break
            if (
                waiver.get("package_name")
                and waiver["package_name"] == finding.component
            ):
                is_waived = True
                break

        if is_waived:
            finding.waived = True
        else:
            final_findings.append(finding)

    # Store Results
    await db.analysis_results.insert_one(
        {
            "_id": str(uuid.uuid4()),
            "scan_id": scan_id,
            "analyzer_name": "kics",
            "result": kics_result,
            "created_at": datetime.now(timezone.utc),
        }
    )

    # Update Scan
    stats = Stats()
    for f in final_findings:
        sev = f.severity.lower()
        if sev == "critical":
            stats.critical += 1
        elif sev == "high":
            stats.high += 1
        elif sev == "medium":
            stats.medium += 1
        elif sev == "low":
            stats.low += 1
        elif sev == "info":
            stats.info += 1
        else:
            stats.unknown += 1

    await worker_manager.add_job(scan_id)

    await db.projects.update_one(
        {"_id": str(project.id)}, {"$set": {"last_scan_at": datetime.now(timezone.utc)}}
    )

    return {
        "scan_id": scan_id,
        "findings_count": len(final_findings),
        "stats": stats.dict(),
    }


@router.post("/ingest/bearer", summary="Ingest Bearer Results", status_code=200)
async def ingest_bearer(
    data: BearerIngest,
    project: Project = Depends(deps.get_project_for_ingest),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    Ingest Bearer SAST/Data Security scan results.
    """
    # Extract metadata
    pipeline_id = data.pipeline_id
    pipeline_iid = data.pipeline_iid

    # Construct Pipeline URL if missing
    pipeline_url = data.pipeline_url
    if not pipeline_url and data.project_url and pipeline_id:
        pipeline_url = f"{data.project_url}/-/pipelines/{pipeline_id}"

    # 1. Find or Create Scan Record (Pipeline)
    existing_scan = None
    if pipeline_id:
        existing_scan = await db.scans.find_one(
            {"project_id": str(project.id), "pipeline_id": pipeline_id}
        )

    if existing_scan:
        scan_id = existing_scan["_id"]
        await db.scans.update_one(
            {"_id": scan_id},
            {
                "$set": {
                    "updated_at": datetime.now(timezone.utc),
                    "branch": data.branch or existing_scan.get("branch"),
                    "commit_hash": data.commit_hash or existing_scan.get("commit_hash"),
                    "project_url": data.project_url,
                    "pipeline_url": pipeline_url,
                    "job_id": data.job_id,
                    "job_started_at": data.job_started_at,
                    "project_name": data.project_name,
                    "commit_message": data.commit_message,
                    "commit_tag": data.commit_tag,
                    "pipeline_user": data.pipeline_user,
                    "status": "pending",  # Force pending to trigger re-aggregation
                }
            },
        )
    else:
        scan = Scan(
            project_id=str(project.id),
            branch=data.branch or "unknown",
            commit_hash=data.commit_hash,
            pipeline_id=pipeline_id,
            pipeline_iid=pipeline_iid,
            project_url=data.project_url,
            pipeline_url=pipeline_url,
            job_id=data.job_id,
            job_started_at=data.job_started_at,
            project_name=data.project_name,
            commit_message=data.commit_message,
            commit_tag=data.commit_tag,
            pipeline_user=data.pipeline_user,
            status="pending",
            created_at=datetime.now(timezone.utc),
        )
        await db.scans.insert_one(scan.dict(by_alias=True))
        scan_id = scan.id

    aggregator = ResultAggregator()
    bearer_result = data.dict()

    aggregator.aggregate("bearer", bearer_result)
    findings = aggregator.get_findings()

    # Apply Waivers
    waivers_cursor = db.waivers.find(
        {
            "$or": [{"project_id": str(project.id)}, {"project_id": None}],
            "expiration_date": {"$gt": datetime.now(timezone.utc)},
        }
    )
    waivers = await waivers_cursor.to_list(length=1000)

    final_findings = []

    for finding in findings:
        is_waived = False
        for waiver in waivers:
            if waiver.get("finding_id") and waiver["finding_id"] == finding.id:
                is_waived = True
                break
            if waiver.get("finding_type") and waiver["finding_type"] == finding.type:
                is_waived = True
                break
            if (
                waiver.get("package_name")
                and waiver["package_name"] == finding.component
            ):
                is_waived = True
                break

        if is_waived:
            finding.waived = True
        else:
            final_findings.append(finding)

    # Store Results
    await db.analysis_results.insert_one(
        {
            "_id": str(uuid.uuid4()),
            "scan_id": scan_id,
            "analyzer_name": "bearer",
            "result": bearer_result,
            "created_at": datetime.now(timezone.utc),
        }
    )

    # Update Scan
    stats = Stats()
    for f in final_findings:
        sev = f.severity.lower()
        if sev == "critical":
            stats.critical += 1
        elif sev == "high":
            stats.high += 1
        elif sev == "medium":
            stats.medium += 1
        elif sev == "low":
            stats.low += 1
        elif sev == "info":
            stats.info += 1
        else:
            stats.unknown += 1

    await worker_manager.add_job(scan_id)

    await db.projects.update_one(
        {"_id": str(project.id)}, {"$set": {"last_scan_at": datetime.now(timezone.utc)}}
    )

    return {
        "scan_id": scan_id,
        "findings_count": len(final_findings),
        "stats": stats.dict(),
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
        "retention_days": project.retention_days,
    }
