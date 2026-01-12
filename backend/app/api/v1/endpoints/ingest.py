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
from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException
from motor.motor_asyncio import AsyncIOMotorDatabase, AsyncIOMotorGridFSBucket

from app.api import deps
from app.db.mongodb import get_database
from app.models.dependency import Dependency
from app.models.project import Project, Scan
from app.schemas.bearer import BearerIngest
from app.schemas.ingest import SBOMIngest
from app.schemas.kics import KicsIngest
from app.schemas.opengrep import OpenGrepIngest
from app.schemas.trufflehog import TruffleHogIngest
from app.services.aggregator import ResultAggregator
from app.services.sbom_parser import parse_sbom
from app.services.scan_manager import ScanManager

logger = logging.getLogger(__name__)

router = APIRouter()


# =============================================================================
# Helper Functions
# =============================================================================


async def _process_findings_ingest(
    manager: ScanManager,
    analyzer_name: str,
    result_dict: Dict[str, Any],
    scan_id: str,
) -> Dict[str, Any]:
    """
    Common processing for findings-based ingests (TruffleHog, OpenGrep, KICS, Bearer).

    1. Normalize findings via aggregator
    2. Apply waivers
    3. Store results
    4. Compute stats
    5. Register result (does NOT trigger aggregation - waits for all scanners)
    6. Update project timestamp

    Returns response dict with scan_id, findings_count, and stats.
    
    Note: Unlike SBOM ingestion, findings-based scanners do NOT trigger
    the aggregation immediately. This prevents race conditions where a fast
    scanner (e.g., SAST) completes before slower scanners (e.g., SBOM),
    causing the scan to be marked as 'completed' prematurely.
    
    The aggregation is triggered either:
    - By the SBOM scanner (which typically runs last and is the "main" analysis)
    - By the housekeeping job if no new results arrive for a configured period
    """
    # Normalize findings
    aggregator = ResultAggregator()
    aggregator.aggregate(analyzer_name, result_dict)
    findings = aggregator.get_findings()

    # Apply waivers
    final_findings, waived_count = await manager.apply_waivers(findings)

    # Store results
    await manager.store_results(analyzer_name, result_dict, scan_id)

    # Compute stats
    stats = ScanManager.compute_stats(final_findings)

    # Register result WITHOUT triggering aggregation
    # This updates last_result_at and received_results, and resets status
    # to 'pending' if it was 'completed' (for late arrivals)
    await manager.register_result(scan_id, analyzer_name, trigger_analysis=False)
    
    # Update project timestamp
    await manager.update_project_last_scan()

    return {
        "scan_id": scan_id,
        "findings_count": len(final_findings),
        "waived_count": waived_count,
        "stats": stats.model_dump(),
    }


# =============================================================================
# Ingest Endpoints
# =============================================================================


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
    manager = ScanManager(db, project)
    ctx = await manager.find_or_create_scan(data)

    # Prepare result dict
    result_dict = {"findings": [f.model_dump() for f in data.findings]}

    # Process findings
    response = await _process_findings_ingest(
        manager, "trufflehog", result_dict, ctx.scan_id
    )

    # TruffleHog returns failure status if secrets found
    failed = response["findings_count"] > 0

    return {
        "status": "failed" if failed else "success",
        "scan_id": response["scan_id"],
        "findings_count": response["findings_count"],
        "waived_count": response["waived_count"],
        "message": f"Found {response['findings_count']} secrets (Waived: {response['waived_count']})",
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
    manager = ScanManager(db, project)
    ctx = await manager.find_or_create_scan(data)

    # Prepare result dict
    result_dict = {"findings": [f.model_dump() for f in data.findings]}

    return await _process_findings_ingest(manager, "opengrep", result_dict, ctx.scan_id)


@router.post("/ingest/kics", summary="Ingest KICS Results", status_code=200)
async def ingest_kics(
    data: KicsIngest,
    project: Project = Depends(deps.get_project_for_ingest),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    Ingest KICS IaC scan results.
    """
    manager = ScanManager(db, project)
    ctx = await manager.find_or_create_scan(data)

    # KICS uses the full model
    result_dict = data.model_dump()

    return await _process_findings_ingest(manager, "kics", result_dict, ctx.scan_id)


@router.post("/ingest/bearer", summary="Ingest Bearer Results", status_code=200)
async def ingest_bearer(
    data: BearerIngest,
    project: Project = Depends(deps.get_project_for_ingest),
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    """
    Ingest Bearer SAST/Data Security scan results.
    """
    manager = ScanManager(db, project)
    ctx = await manager.find_or_create_scan(data)

    # Bearer uses the full model
    result_dict = data.model_dump()

    return await _process_findings_ingest(manager, "bearer", result_dict, ctx.scan_id)


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
    manager = ScanManager(db, project)

    if not data.sboms:
        raise HTTPException(status_code=400, detail="No SBOM provided")

    # For SBOM, we need the scan_id before creating the scan for GridFS metadata
    # So we handle this slightly differently
    pipeline_url = manager._build_pipeline_url(data)

    # Check for existing scan
    existing_scan = None
    if data.pipeline_id:
        existing_scan = await db.scans.find_one(
            {"project_id": str(project.id), "pipeline_id": data.pipeline_id}
        )

    scan_id = existing_scan["_id"] if existing_scan else str(uuid.uuid4())

    # Initialize GridFS
    fs = AsyncIOMotorGridFSBucket(db)
    sbom_refs = []
    dependencies_to_insert = []

    for sbom in data.sboms:
        # Upload to GridFS
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
                    "type": "gridfs_reference",
                    "gridfs_id": str(file_id),
                }
            )
        except Exception as e:
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

        except Exception as e:
            logger.error(
                f"Failed to extract dependencies from SBOM: {e}", exc_info=True
            )

    # Bulk insert dependencies
    if dependencies_to_insert:
        try:
            if existing_scan:
                await db.dependencies.delete_many({"scan_id": scan_id})
            await db.dependencies.insert_many(dependencies_to_insert)
        except Exception as e:
            logger.error(f"Failed to insert dependencies: {e}")

    # Create or update scan using manager's context
    # We need to do this after GridFS to include sbom_refs
    if existing_scan:
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
                    "status": "pending",
                    "updated_at": datetime.now(timezone.utc),
                },
                "$push": {"sbom_refs": {"$each": sbom_refs}},
            },
        )
    else:
        scan = Scan(
            id=scan_id,
            project_id=str(project.id),
            branch=data.branch or "unknown",
            commit_hash=data.commit_hash,
            pipeline_id=data.pipeline_id,
            pipeline_iid=data.pipeline_iid,
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
        await db.scans.insert_one(scan.model_dump(by_alias=True))

    # Register SBOM result and trigger analysis
    # SBOM is considered the "main" scanner, so it triggers aggregation
    # This will also collect results from other scanners (TruffleHog, OpenGrep, etc.)
    # that may have already submitted their findings
    await manager.register_result(scan_id, "sbom", trigger_analysis=True)

    return {
        "status": "queued",
        "scan_id": scan_id,
        "message": "Analysis queued successfully",
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
