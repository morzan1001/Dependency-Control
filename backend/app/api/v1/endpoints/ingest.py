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
from typing import Annotated, Any, Dict, List
from datetime import datetime, timezone

from fastapi import Depends, HTTPException

from app.api.router import CustomAPIRouter
from app.api.v1.helpers.responses import RESP_AUTH, RESP_AUTH_400_500
from motor.motor_asyncio import AsyncIOMotorGridFSBucket

from app.api import deps
from app.api.deps import DatabaseDep
from app.api.v1.helpers.ingest import process_findings_ingest
from app.models.dependency import Dependency
from app.models.project import Project
from app.repositories import DependencyRepository
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

ProjectIngestDep = Annotated[Project, Depends(deps.get_project_for_ingest)]

logger = logging.getLogger(__name__)

router = CustomAPIRouter()


@router.post(
    "/ingest/trufflehog",
    summary="Ingest TruffleHog Results",
    status_code=200,
    responses=RESP_AUTH,
)
async def ingest_trufflehog(
    data: TruffleHogIngest,
    project: ProjectIngestDep,
    db: DatabaseDep,
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
    response = await process_findings_ingest(manager, "trufflehog", result_dict, ctx.scan_id)

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
    status_code=200,
    responses=RESP_AUTH,
)
async def ingest_opengrep(
    data: OpenGrepIngest,
    project: ProjectIngestDep,
    db: DatabaseDep,
) -> FindingsIngestResponse:
    """
    Ingest OpenGrep SAST scan results.
    Returns a summary of findings.
    """
    manager = ScanManager(db, project)
    ctx = await manager.find_or_create_scan(data)

    # Prepare result dict
    result_dict = {"findings": [f.model_dump() for f in data.findings]}

    response = await process_findings_ingest(manager, "opengrep", result_dict, ctx.scan_id)
    return FindingsIngestResponse(**response)


@router.post(
    "/ingest/kics",
    summary="Ingest KICS Results",
    status_code=200,
    responses=RESP_AUTH,
)
async def ingest_kics(
    data: KicsIngest,
    project: ProjectIngestDep,
    db: DatabaseDep,
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
    status_code=200,
    responses=RESP_AUTH,
)
async def ingest_bearer(
    data: BearerIngest,
    project: ProjectIngestDep,
    db: DatabaseDep,
) -> FindingsIngestResponse:
    """
    Ingest Bearer SAST/Data Security scan results.
    """
    manager = ScanManager(db, project)
    ctx = await manager.find_or_create_scan(data)

    # Bearer uses the full model
    result_dict = data.model_dump()

    response = await process_findings_ingest(manager, "bearer", result_dict, ctx.scan_id)
    return FindingsIngestResponse(**response)


def _generate_scan_id(project_id: str, pipeline_id: int | str | None, commit_hash: str | None) -> str:
    """Generate a deterministic or random scan ID based on available pipeline context."""
    if pipeline_id and commit_hash:
        scan_id_seed = f"{project_id}-{pipeline_id}-{commit_hash}"
        return str(uuid.uuid5(uuid.NAMESPACE_DNS, scan_id_seed))
    if pipeline_id:
        scan_id_seed = f"{project_id}-{pipeline_id}"
        return str(uuid.uuid5(uuid.NAMESPACE_DNS, scan_id_seed))
    return str(uuid.uuid4())


def _parsed_dep_to_dependency(parsed_dep: Any, project_id: str, scan_id: str) -> Dependency:
    """Convert a parsed dependency to a Dependency model."""
    return Dependency(
        project_id=project_id,
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


async def _upload_sbom_to_gridfs(fs: AsyncIOMotorGridFSBucket, sbom: Any, scan_id: str) -> Dict[str, Any]:
    """Upload a single SBOM to GridFS and return the reference dict."""
    filename = f"sbom-{uuid.uuid4()}.json"
    sbom_bytes = json.dumps(sbom).encode("utf-8")
    file_id = await fs.upload_from_stream(
        filename,
        sbom_bytes,
        metadata={"contentType": "application/json", "scan_id": scan_id},
    )
    del sbom_bytes
    return {
        "storage": "gridfs",
        "file_id": str(file_id),
        "filename": filename,
        "type": "gridfs_reference",
        "gridfs_id": str(file_id),
    }


_DEP_CHUNK_SIZE = 500


async def _process_sboms(
    sboms: List[Any],
    fs: AsyncIOMotorGridFSBucket,
    project_id: str,
    scan_id: str,
    dep_repo: "DependencyRepository",
) -> tuple[List[Dict[str, Any]], List[str], int, int, int]:
    """Process all SBOMs: upload to GridFS and extract dependencies.

    Dependencies are inserted in chunks to limit peak memory usage.

    Returns:
        Tuple of (sbom_refs, warnings, sboms_processed, sboms_failed, total_deps_inserted)
    """
    sbom_refs: List[Dict[str, Any]] = []
    warnings: List[str] = []
    sboms_processed = 0
    sboms_failed = 0
    total_deps_inserted = 0
    old_deps_deleted = False

    for idx, sbom in enumerate(sboms):
        try:
            ref = await _upload_sbom_to_gridfs(fs, sbom, scan_id)
            sbom_refs.append(ref)
        except Exception as e:
            sboms_failed += 1
            warnings.append(f"SBOM {idx + 1}: Failed to upload to storage")
            logger.error(f"Failed to upload SBOM to GridFS: {e}")
            continue

        try:
            parsed_sbom = parse_sbom(sbom)
            logger.info(
                f"Parsed SBOM: format={parsed_sbom.format.value}, "
                f"total={parsed_sbom.total_components}, "
                f"parsed={parsed_sbom.parsed_components}, "
                f"skipped={parsed_sbom.skipped_components}"
            )

            # Delete old dependencies once before the first insert
            if not old_deps_deleted:
                deleted_count = await dep_repo.delete_by_scan(scan_id)
                if deleted_count:
                    logger.debug(f"Deleted {deleted_count} old dependencies for scan {scan_id}")
                old_deps_deleted = True

            # Insert dependencies in chunks instead of accumulating all in memory
            chunk: List[Dict[str, Any]] = []
            for parsed_dep in parsed_sbom.dependencies:
                dep = _parsed_dep_to_dependency(parsed_dep, project_id, scan_id)
                chunk.append(dep.model_dump(by_alias=True))
                if len(chunk) >= _DEP_CHUNK_SIZE:
                    total_deps_inserted += await dep_repo.create_many_raw(chunk)
                    chunk.clear()
            if chunk:
                total_deps_inserted += await dep_repo.create_many_raw(chunk)
                chunk.clear()

            sboms_processed += 1
        except Exception as e:
            sboms_failed += 1
            warnings.append(f"SBOM {idx + 1}: Failed to parse dependencies")
            logger.error(f"Failed to extract dependencies from SBOM: {e}", exc_info=True)

    return sbom_refs, warnings, sboms_processed, sboms_failed, total_deps_inserted


@router.post(
    "/ingest",
    summary="Ingest SBOM",
    status_code=202,
    responses=RESP_AUTH_400_500,
)
async def ingest_sbom(
    data: SBOMIngest,
    project: ProjectIngestDep,
    db: DatabaseDep,
) -> SBOMIngestResponse:
    """
    Upload an SBOM for analysis.

    Requires a valid **API Key** in the `X-API-Key` header or **OIDC Token** (GitLab/GitHub Actions) in the `Job-Token` header.
    The analysis will be queued and processed by background workers.
    """
    manager = ScanManager(db, project)
    dep_repo = DependencyRepository(db)

    if not data.sboms:
        raise HTTPException(status_code=400, detail="No SBOM provided")

    pipeline_url = manager.build_pipeline_url(data)
    scan_id = _generate_scan_id(str(project.id), data.pipeline_id, data.commit_hash)

    # Initialize GridFS and process all SBOMs (dependencies inserted in chunks)
    fs = AsyncIOMotorGridFSBucket(db)
    try:
        sbom_refs, warnings, sboms_processed, sboms_failed, total_deps_inserted = await _process_sboms(
            data.sboms, fs, str(project.id), scan_id, dep_repo
        )
    except Exception as e:
        logger.error(f"Failed to process SBOMs: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail="Failed to store dependencies. Please try again.",
        )

    # Fail if ALL SBOMs failed to process
    if sboms_failed > 0 and sboms_processed == 0:
        raise HTTPException(
            status_code=400,
            detail=f"All {sboms_failed} SBOM(s) failed to process. Check server logs for details.",
        )

    if total_deps_inserted:
        logger.info(f"Inserted {total_deps_inserted} dependencies for scan {scan_id}")

    now = datetime.now(timezone.utc)

    scan_update: Dict[str, Any] = {
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

    # Add new SBOM refs (append to existing, or initialize if new)
    if sbom_refs:
        scan_update["$push"] = {"sbom_refs": {"$each": sbom_refs}}
    else:
        scan_update["$setOnInsert"]["sbom_refs"] = []

    # Atomic upsert
    await db.scans.update_one({"_id": scan_id}, scan_update, upsert=True)

    # If scan was completed, reset to pending for re-analysis
    await db.scans.update_one(
        {"_id": scan_id, "status": "completed"},
        {"$set": {"status": "pending", "retry_count": 0}},
    )

    # Register SBOM result and trigger analysis
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
        dependencies_count=total_deps_inserted,
        warnings=warnings,
    )


@router.get(
    "/ingest/config",
    summary="Get Project Configuration",
    status_code=200,
    responses=RESP_AUTH,
)
async def get_project_config(
    project: ProjectIngestDep,
) -> ProjectConfigResponse:
    """
    Get project configuration for CI/CD pipelines.
    Returns active analyzers and other settings.
    """
    return ProjectConfigResponse(
        active_analyzers=project.active_analyzers,
        retention_days=project.retention_days,
    )
