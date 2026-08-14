"""Ingest endpoints for scan results from security tools (SBOM, TruffleHog, OpenGrep, KICS, Bearer)."""

import asyncio
import json
import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Annotated, Any

from fastapi import Depends, HTTPException
from motor.motor_asyncio import AsyncIOMotorGridFSBucket
from pymongo import ReturnDocument

from app.api import deps
from app.api.deps import DatabaseDep
from app.api.router import CustomAPIRouter
from app.api.v1.helpers.ingest import process_findings_ingest
from app.api.v1.helpers.responses import RESP_AUTH, RESP_AUTH_400_500
from app.core.constants import SCAN_USABLE_STATUSES, WEBHOOK_EVENT_SBOM_INGESTED
from app.models.project import Project
from app.repositories import DependencyRepository, DistributedLocksRepository
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
from app.services.dependency_store import store_scan_dependencies
from app.services.gridfs_maintenance import cleanup_gridfs_files, extract_gridfs_ids_from_refs
from app.services.notifications.service import safe_notify_project_event
from app.services.sbom_parser import merge_duplicate_dependencies, parse_sbom
from app.services.scan_manager import ScanManager
from app.services.webhooks import webhook_service

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
    """Ingest TruffleHog secret scan results; returns findings summary and pipeline failure status."""
    manager = ScanManager(db, project)
    ctx = await manager.find_or_create_scan(data)

    result_dict = {"findings": [f.model_dump() for f in data.findings]}

    response = await process_findings_ingest(manager, "trufflehog", result_dict, ctx.scan_id)

    # Any secret found fails the pipeline.
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
    """Ingest OpenGrep SAST scan results; returns a findings summary."""
    manager = ScanManager(db, project)
    ctx = await manager.find_or_create_scan(data)

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
    """Ingest KICS IaC scan results."""
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
    """Ingest Bearer SAST/Data Security scan results."""
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


async def _upload_sbom_to_gridfs(fs: AsyncIOMotorGridFSBucket, sbom: Any, scan_id: str) -> dict[str, Any]:
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


def _parse_one_sbom(sbom: Any, index: int, warnings: list[str]) -> Any:
    """Parse one SBOM; surfaces skipped-component loss as a response warning."""
    parsed_sbom = parse_sbom(sbom)
    logger.info(
        f"Parsed SBOM: format={parsed_sbom.format.value}, "
        f"total={parsed_sbom.total_components}, "
        f"parsed={parsed_sbom.parsed_components}, "
        f"skipped={parsed_sbom.skipped_components}, "
        f"merged={parsed_sbom.merged_components}, "
        f"skipped_reasons={parsed_sbom.skipped_reasons}"
    )
    if parsed_sbom.skipped_components:
        reasons = ", ".join(f"{reason}: {count}" for reason, count in sorted(parsed_sbom.skipped_reasons.items()))
        warnings.append(
            f"SBOM {index + 1}: skipped {parsed_sbom.skipped_components} of "
            f"{parsed_sbom.total_components} components ({reasons})"
        )
    return parsed_sbom


async def _process_sboms(
    sboms: list[Any],
    fs: AsyncIOMotorGridFSBucket,
    project_id: str,
    scan_id: str,
    dep_repo: "DependencyRepository",
) -> tuple[list[dict[str, Any]], list[str], int, int, int]:
    """Upload and parse ALL SBOMs before the first dependency write; returns
    (sbom_refs, warnings, sboms_processed, sboms_failed, total_deps_inserted).

    The scan's dependency inventory is replaced only when every SBOM uploaded and
    parsed, so a mixed [good, malformed] payload cannot wipe a prior contribution.
    """
    sbom_refs: list[dict[str, Any]] = []
    warnings: list[str] = []
    parsed_sboms: list[Any] = []
    sboms_failed = 0

    for idx, sbom in enumerate(sboms):
        try:
            ref = await _upload_sbom_to_gridfs(fs, sbom, scan_id)
            sbom_refs.append(ref)
        except Exception as e:
            sboms_failed += 1
            warnings.append(f"SBOM {idx + 1}: Failed to upload to storage")
            logger.exception("Failed to upload SBOM to GridFS: %s", e)
            continue

        try:
            parsed_sboms.append(_parse_one_sbom(sbom, idx, warnings))
        except Exception as e:
            sboms_failed += 1
            warnings.append(f"SBOM {idx + 1}: Failed to parse dependencies")
            logger.exception("Failed to extract dependencies from SBOM: %s", e)

    total_deps_inserted = 0
    if sboms_failed:
        if parsed_sboms:
            warnings.append("Dependency inventory left unchanged: at least one SBOM of this payload failed to process")
    else:
        # The unique index spans the scan, so duplicates across the payload's SBOMs must be
        # merged before the first insert or the later ones lose their locations/CPEs/parents.
        dependencies, _ = merge_duplicate_dependencies(
            [dep for parsed_sbom in parsed_sboms for dep in parsed_sbom.dependencies]
        )
        total_deps_inserted = await store_scan_dependencies(dependencies, project_id, scan_id, dep_repo)
        if total_deps_inserted < len(dependencies):
            warnings.append(f"Only {total_deps_inserted} of {len(dependencies)} parsed dependencies were stored")

    return sbom_refs, warnings, len(parsed_sboms), sboms_failed, total_deps_inserted


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
    """Upload an SBOM for analysis; the analysis is queued and processed by background workers."""
    manager = ScanManager(db, project)
    dep_repo = DependencyRepository(db)

    if not data.sboms:
        raise HTTPException(status_code=400, detail="No SBOM provided")

    pipeline_url = manager.build_pipeline_url(data)
    scan_id = _generate_scan_id(str(project.id), data.pipeline_id, data.commit_hash)

    # Serialise concurrent ingests of the same scan_id (CI retries) best-effort.
    lock_repo = DistributedLocksRepository(db)
    lock_name = f"sbom_ingest:{scan_id}"
    lock_holder = f"ingest-{os.getenv('HOSTNAME', 'unknown')}-{uuid.uuid4().hex[:8]}"
    locked = False
    for _ in range(20):
        locked = await lock_repo.acquire_lock(lock_name, lock_holder, ttl_seconds=120)
        if locked:
            break
        await asyncio.sleep(0.5)
    if not locked:
        logger.warning("Proceeding without ingest lock for scan %s (concurrent ingest still running?)", scan_id)

    try:
        fs = AsyncIOMotorGridFSBucket(db)
        try:
            sbom_refs, warnings, sboms_processed, sboms_failed, total_deps_inserted = await _process_sboms(
                data.sboms, fs, str(project.id), scan_id, dep_repo
            )
        except Exception as e:
            logger.exception("Failed to process SBOMs: %s", e)
            raise HTTPException(
                status_code=500,
                detail="Failed to store dependencies. Please try again.",
            )

        if sboms_failed > 0 and sboms_processed == 0:
            raise HTTPException(
                status_code=400,
                detail=f"All {sboms_failed} SBOM(s) failed to process. Check server logs for details.",
            )

        if total_deps_inserted:
            logger.info(f"Inserted {total_deps_inserted} dependencies for scan {scan_id}")

        now = datetime.now(timezone.utc)

        scan_update: dict[str, Any] = {
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

        # Replace (never append) so a CI retry cannot pile up duplicate SBOMs that get
        # stored and re-analysed forever; superseded GridFS uploads are deleted below.
        if sbom_refs:
            scan_update["$set"]["sbom_refs"] = sbom_refs
        else:
            scan_update["$setOnInsert"]["sbom_refs"] = []

        previous = await db.scans.find_one_and_update(
            {"_id": scan_id}, scan_update, upsert=True, return_document=ReturnDocument.BEFORE
        )

        if previous and sbom_refs:
            new_ids = {ref["gridfs_id"] for ref in sbom_refs}
            superseded = [
                gid for gid in extract_gridfs_ids_from_refs(previous.get("sbom_refs", [])) if gid not in new_ids
            ]
            if superseded:
                await cleanup_gridfs_files(db, superseded)

        # Reset a finished scan to pending so re-ingest re-analyses it.
        await db.scans.update_one(
            {"_id": scan_id, "status": {"$in": SCAN_USABLE_STATUSES}},
            {"$set": {"status": "pending", "retry_count": 0}},
        )

        await manager.register_result(scan_id, "sbom", trigger_analysis=True)
    finally:
        if locked:
            await lock_repo.release_lock(lock_name, lock_holder)

    # Fire ingest webhook (best-effort).
    await webhook_service.safe_trigger_webhooks(
        db,
        WEBHOOK_EVENT_SBOM_INGESTED,
        {
            "scan_id": scan_id,
            "project_id": str(project.id),
            "pipeline_id": data.pipeline_id,
            "commit_hash": data.commit_hash,
            "branch": data.branch,
            "sboms_processed": sboms_processed,
            "sboms_failed": sboms_failed,
            "dependencies_count": total_deps_inserted,
        },
        str(project.id),
        context="sbom_ingest",
    )

    await safe_notify_project_event(
        db,
        project_id=str(project.id),
        event_type="sbom_ingested",
        subject=f"SBOM ingested: {project.name}",
        message=f"{sboms_processed} SBOM(s) ingested for project {project.name} ({total_deps_inserted} dependencies).",
        context="sbom_ingest",
    )

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
    """Get project configuration (active analyzers and settings) for CI/CD pipelines."""
    return ProjectConfigResponse(
        active_analyzers=project.active_analyzers,
        retention_days=project.retention_days,
    )
