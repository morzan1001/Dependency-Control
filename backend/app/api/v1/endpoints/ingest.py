"""
Ingest API Endpoints - Refactored Version

This module handles ingestion of scan results from various security tools:
- SBOM (Software Bill of Materials)
- TruffleHog (Secret scanning)
- OpenGrep (SAST)
- KICS (IaC scanning)
- Bearer (Data security)
"""

import json
import logging
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from motor.motor_asyncio import AsyncIOMotorDatabase, AsyncIOMotorGridFSBucket

from app.api import deps
from app.api.v1.helpers.ingest import process_findings_ingest
from app.db.mongodb import get_database
from app.models.dependency import Dependency
from app.models.project import Project, Scan
from app.repositories import DependencyRepository, ScanRepository
from app.schemas.bearer import BearerIngest
from app.schemas.ingest import (
    FindingsIngestResponse,
    ProjectConfigResponse,
    SBOMIngest,
    SBOMIngestResponse,
    SecretScanResponse,
)
from app.schemas.kics import KicsIngest
from app.schemas.opengrep import OpenGrepIngest
from app.schemas.trufflehog import TruffleHogIngest
from app.services.sbom_parser import parse_sbom
from app.services.scan_manager import ScanManager

logger = logging.getLogger(__name__)

router = APIRouter()


@router.post(
    "/ingest/trufflehog",
    summary="Ingest TruffleHog Results",
    response_model=SecretScanResponse,
    status_code=200,
)
async def ingest_trufflehog(
    data: TruffleHogIngest,
    project: Project = Depends(deps.get_project_for_ingest),
    db: AsyncIOMotorDatabase = Depends(get_database),
) -> SecretScanResponse:
    """
    Ingest TruffleHog secret scan results.
    Returns a summary of findings and pipeline failure status.
    """
    manager = ScanManager(db, project)
    ctx = await manager.find_or_create_scan(data)

    # Prepare result dict
    result_dict = {"findings": [f.model_dump() for f in data.findings]}

    # Process findings
    response = await process_findings_ingest(
        manager, "trufflehog", result_dict, ctx.scan_id
    )

    # TruffleHog returns failure status if secrets found
    failed = response["findings_count"] > 0

    return SecretScanResponse(
        status="failed" if failed else "success",
        scan_id=response["scan_id"],
        findings_count=response["findings_count"],
        waived_count=response["waived_count"],
        message=f"Found {response['findings_count']} secrets (Waived: {response['waived_count']})",
    )


@router.post(
    "/ingest/opengrep",
    summary="Ingest OpenGrep Results",
    response_model=FindingsIngestResponse,
    status_code=200,
)
async def ingest_opengrep(
    data: OpenGrepIngest,
    project: Project = Depends(deps.get_project_for_ingest),
    db: AsyncIOMotorDatabase = Depends(get_database),
) -> FindingsIngestResponse:
    """
    Ingest OpenGrep SAST scan results.
    Returns a summary of findings.
    """
    manager = ScanManager(db, project)
    ctx = await manager.find_or_create_scan(data)

    # Prepare result dict
    result_dict = {"findings": [f.model_dump() for f in data.findings]}

    response = await process_findings_ingest(
        manager, "opengrep", result_dict, ctx.scan_id
    )
    return FindingsIngestResponse(**response)


@router.post(
    "/ingest/kics",
    summary="Ingest KICS Results",
    response_model=FindingsIngestResponse,
    status_code=200,
)
async def ingest_kics(
    data: KicsIngest,
    project: Project = Depends(deps.get_project_for_ingest),
    db: AsyncIOMotorDatabase = Depends(get_database),
) -> FindingsIngestResponse:
    """
    Ingest KICS IaC scan results.
    """
    manager = ScanManager(db, project)
    ctx = await manager.find_or_create_scan(data)

    # KICS uses the full model
    result_dict = data.model_dump()

    response = await process_findings_ingest(manager, "kics", result_dict, ctx.scan_id)
    return FindingsIngestResponse(**response)


@router.post(
    "/ingest/bearer",
    summary="Ingest Bearer Results",
    response_model=FindingsIngestResponse,
    status_code=200,
)
async def ingest_bearer(
    data: BearerIngest,
    project: Project = Depends(deps.get_project_for_ingest),
    db: AsyncIOMotorDatabase = Depends(get_database),
) -> FindingsIngestResponse:
    """
    Ingest Bearer SAST/Data Security scan results.
    """
    manager = ScanManager(db, project)
    ctx = await manager.find_or_create_scan(data)

    # Bearer uses the full model
    result_dict = data.model_dump()

    response = await process_findings_ingest(
        manager, "bearer", result_dict, ctx.scan_id
    )
    return FindingsIngestResponse(**response)


@router.post(
    "/ingest",
    summary="Ingest SBOM",
    response_model=SBOMIngestResponse,
    status_code=202,
)
async def ingest_sbom(
    data: SBOMIngest,
    project: Project = Depends(deps.get_project_for_ingest),
    db: AsyncIOMotorDatabase = Depends(get_database),
) -> SBOMIngestResponse:
    """
    Upload an SBOM for analysis.

    Requires a valid **API Key** in the `X-API-Key` header or **GitLab OIDC Token**.
    The analysis will be queued and processed by background workers.
    """
    manager = ScanManager(db, project)
    scan_repo = ScanRepository(db)
    dep_repo = DependencyRepository(db)

    if not data.sboms:
        raise HTTPException(status_code=400, detail="No SBOM provided")

    pipeline_url = manager.build_pipeline_url(data)

    if data.pipeline_id and data.commit_hash:
        # Deterministic scan_id: Same commit in same pipeline = same scan
        scan_id_seed = f"{project.id}-{data.pipeline_id}-{data.commit_hash}"
        scan_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, scan_id_seed))
    elif data.pipeline_id:
        # No commit_hash, use pipeline_id only (less precise, but better than random)
        scan_id_seed = f"{project.id}-{data.pipeline_id}"
        scan_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, scan_id_seed))
    else:
        # No pipeline_id, use random UUID (manual upload scenario)
        scan_id = str(uuid.uuid4())

    # Initialize GridFS
    fs = AsyncIOMotorGridFSBucket(db)
    sbom_refs = []
    dependencies_to_insert = []
    warnings: list[str] = []
    sboms_processed = 0
    sboms_failed = 0

    for idx, sbom in enumerate(data.sboms):
        # Upload to GridFS
        try:
            sbom_str = json.dumps(sbom)
            sbom_bytes = sbom_str.encode("utf-8")
            # Generate consistent filename UUID
            filename = f"sbom-{uuid.uuid4()}.json"
            file_id = await fs.upload_from_stream(
                filename,
                sbom_bytes,
                metadata={"contentType": "application/json", "scan_id": scan_id},
            )
            sbom_refs.append(
                {
                    "storage": "gridfs",
                    "file_id": str(file_id),
                    "filename": filename,  # Use same filename
                    "type": "gridfs_reference",
                    "gridfs_id": str(file_id),
                }
            )
        except Exception as e:
            sboms_failed += 1
            warning_msg = f"SBOM {idx + 1}: Failed to upload to storage"
            warnings.append(warning_msg)
            logger.error(f"Failed to upload SBOM to GridFS: {e}")
            continue

        # Extract Dependencies
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
                    name=parsed_dep.name,
                    version=parsed_dep.version,
                    purl=parsed_dep.purl,
                    type=parsed_dep.type,
                    license=parsed_dep.license,
                    license_url=parsed_dep.license_url,
                    scope=parsed_dep.scope,
                    direct=parsed_dep.direct,
                    direct_inferred=parsed_dep.direct_inferred,
                    parent_components=parsed_dep.parent_components,
                    source_type=parsed_dep.source_type,
                    source_target=parsed_dep.source_target,
                    layer_digest=parsed_dep.layer_digest,
                    found_by=parsed_dep.found_by,
                    locations=parsed_dep.locations,
                    cpes=parsed_dep.cpes,
                    description=parsed_dep.description,
                    author=parsed_dep.author,
                    publisher=parsed_dep.publisher,
                    group=parsed_dep.group,
                    homepage=parsed_dep.homepage,
                    repository_url=parsed_dep.repository_url,
                    download_url=parsed_dep.download_url,
                    hashes=parsed_dep.hashes,
                    properties=parsed_dep.properties,
                )
                dependencies_to_insert.append(dep.model_dump(by_alias=True))

            sboms_processed += 1

        except Exception as e:
            sboms_failed += 1
            warning_msg = f"SBOM {idx + 1}: Failed to parse dependencies"
            warnings.append(warning_msg)
            logger.error(
                f"Failed to extract dependencies from SBOM: {e}", exc_info=True
            )

    # Fail if ALL SBOMs failed to process
    if sboms_failed > 0 and sboms_processed == 0:
        raise HTTPException(
            status_code=400,
            detail=f"All {sboms_failed} SBOM(s) failed to process. Check server logs for details.",
        )

    # Bulk insert/update dependencies
    if dependencies_to_insert:
        try:
            # Delete old dependencies for this scan atomically
            await dep_repo.delete_by_scan(scan_id)
            # Insert new dependencies (use create_many_raw for dict list)
            # The unique constraint on (scan_id, name, version, purl) prevents duplicates
            await dep_repo.create_many_raw(dependencies_to_insert)
        except Exception as e:
            # Check if this is a duplicate key error (race condition with another pod)
            if "duplicate key error" in str(e).lower() or "E11000" in str(e):
                logger.warning(
                    f"Duplicate dependency detected for scan {scan_id}, "
                    f"likely due to concurrent SBOM upload. Ignoring."
                )
                # Continue processing - the dependencies are already inserted by another pod
            else:
                warnings.append("Failed to store dependencies")
                logger.error(f"Failed to insert dependencies: {e}", exc_info=True)
                # This is critical - if dependencies fail, the scan is incomplete
                raise HTTPException(
                    status_code=500,
                    detail="Failed to store dependencies. Please try again.",
                )

    now = datetime.now(timezone.utc)

    scan_update = {
        "$set": {
            "branch": data.branch or "unknown",
            "commit_hash": data.commit_hash,
            "project_url": data.project_url,
            "pipeline_url": pipeline_url,
            "job_id": data.job_id,
            "job_started_at": data.job_started_at,
            "project_name": data.project_name,
            "commit_message": data.commit_message,
            "commit_tag": data.commit_tag,
            "pipeline_user": data.pipeline_user,
            "updated_at": now,
        },
        "$setOnInsert": {
            "_id": scan_id,
            "project_id": str(project.id),
            "pipeline_id": data.pipeline_id,
            "pipeline_iid": data.pipeline_iid,
            "status": "pending",
            "created_at": now,
        },
    }

    # Only set status to pending if not currently processing
    # This prevents resetting a scan that's actively being analyzed
    filter_query = {"_id": scan_id}

    # Add new SBOM refs (append to existing, or initialize if new)
    if sbom_refs:
        scan_update["$push"] = {"sbom_refs": {"$each": sbom_refs}}
    else:
        # Only initialize sbom_refs as empty array if no sboms provided
        scan_update["$setOnInsert"]["sbom_refs"] = []

    # Atomic upsert
    await db.scans.update_one(
        filter_query,
        scan_update,
        upsert=True,
    )

    # If scan was completed, reset to pending for re-analysis
    # This handles the case where a new SBOM is uploaded for an existing pipeline
    # Also reset retry_count since this is a legitimate new upload, not a retry
    await db.scans.update_one(
        {"_id": scan_id, "status": "completed"},
        {"$set": {"status": "pending", "retry_count": 0}},
    )

    # Register SBOM result and trigger analysis
    # SBOM is considered the "main" scanner, so it triggers aggregation
    await manager.register_result(scan_id, "sbom", trigger_analysis=True)

    # Build response message
    message = "Analysis queued successfully"
    if sboms_failed > 0:
        message = f"Analysis queued with warnings: {sboms_failed} SBOM(s) failed"

    return SBOMIngestResponse(
        status="queued",
        scan_id=scan_id,
        message=message,
        sboms_processed=sboms_processed,
        sboms_failed=sboms_failed,
        dependencies_count=len(dependencies_to_insert),
        warnings=warnings,
    )


@router.get(
    "/ingest/config",
    summary="Get Project Configuration",
    response_model=ProjectConfigResponse,
    status_code=200,
)
async def get_project_config(
    project: Project = Depends(deps.get_project_for_ingest),
) -> ProjectConfigResponse:
    """
    Get project configuration for CI/CD pipelines.
    Returns active analyzers and other settings.
    """
    return ProjectConfigResponse(
        active_analyzers=project.active_analyzers,
        retention_days=project.retention_days,
    )
