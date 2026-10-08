"""Ingest endpoints for scan results from security tools (SBOM, TruffleHog, OpenGrep, KICS, Bearer)."""

import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import BackgroundTasks, HTTPException, Request

from app.api.deps import DatabaseDep, ProjectIngestDep
from app.api.router import CustomAPIRouter
from app.api.v1.helpers.ingest import process_findings_ingest
from app.api.v1.helpers.request_body import read_json_body
from app.api.v1.helpers.responses import RESP_AUTH, RESP_AUTH_400_500
from app.core.constants import (
    NOTIFICATION_EVENT_SBOM_INGESTED,
    SCAN_STATUS_FAILED,
    SCAN_USABLE_STATUSES,
    WEBHOOK_EVENT_SBOM_INGESTED,
)
from app.repositories.scans import ScanRepository
from app.schemas.bearer import BearerIngest
from app.schemas.ingest import (
    BaseIngest,
    FindingsIngestResponse,
    ProjectConfigResponse,
    SBOMIngest,
    SBOMIngestResponse,
    SecretScanResponse,
)
from app.schemas.kics import KicsIngest
from app.schemas.opengrep import OpenGrepIngest
from app.schemas.sbom import SBOMFormat
from app.schemas.trufflehog import TruffleHogIngest
from app.services.gridfs_maintenance import make_gridfs_ref, upload_gridfs_json
from app.services.notifications.service import safe_notify_project_event
from app.services.sbom_parser import sbom_parser
from app.services.scan_manager import ScanManager
from app.services.webhooks import webhook_service


logger = logging.getLogger(__name__)

router = CustomAPIRouter()


@router.post(
    "/ingest/trufflehog",
    summary="Ingest TruffleHog Results",
    status_code=200,
    responses=RESP_AUTH,
)
async def ingest_trufflehog(
    request: Request,
    project: ProjectIngestDep,
    db: DatabaseDep,
) -> SecretScanResponse:
    """Ingest TruffleHog secret scan results; returns findings summary and pipeline failure status."""
    data = await read_json_body(request, TruffleHogIngest)
    response = await process_findings_ingest(ScanManager(db, project), "trufflehog", data)

    # Any secret found fails the pipeline.
    return SecretScanResponse(
        status="failed" if response.findings_count else "success",
        scan_id=response.scan_id,
        findings_count=response.findings_count,
        waived_count=response.waived_count,
        message=f"Found {response.findings_count} secrets (Waived: {response.waived_count})",
    )


def _route_findings_ingest(analyzer: str, label: str, model: type[BaseIngest], description: str) -> None:
    async def ingest(request: Request, project: ProjectIngestDep, db: DatabaseDep) -> FindingsIngestResponse:
        return await process_findings_ingest(ScanManager(db, project), analyzer, await read_json_body(request, model))

    router.post(
        f"/ingest/{analyzer}",
        summary=f"Ingest {label} Results",
        description=description,
        status_code=200,
        responses=RESP_AUTH,
        name=f"ingest_{analyzer}",
    )(ingest)


for _route in (
    ("opengrep", "OpenGrep", OpenGrepIngest, "Ingest OpenGrep SAST scan results; returns a findings summary."),
    ("kics", "KICS", KicsIngest, "Ingest KICS IaC scan results."),
    ("bearer", "Bearer", BearerIngest, "Ingest Bearer SAST/Data Security scan results."),
):
    _route_findings_ingest(*_route)


async def _upload_recognized_sboms(sboms: list[Any], db: Any, scan_id: str) -> list[dict[str, Any]]:
    """Store each CycloneDX, SPDX or Syft document in GridFS, freeing its list slot as it goes; skip the rest."""
    refs = []
    for index, sbom in enumerate(sboms):
        sboms[index] = None
        try:
            sbom_format = sbom_parser.detect_format(sbom)
        except (AttributeError, TypeError):
            sbom_format = SBOMFormat.UNKNOWN
        if sbom_format == SBOMFormat.UNKNOWN:
            continue
        filename = f"sbom-{uuid.uuid4()}.json"
        file_id = await upload_gridfs_json(
            db, filename, sbom, metadata={"contentType": "application/json", "scan_id": scan_id}
        )
        refs.append(make_gridfs_ref(file_id, filename))
    return refs


@router.post(
    "/ingest",
    summary="Ingest SBOM",
    status_code=202,
    responses=RESP_AUTH_400_500,
)
async def ingest_sbom(
    request: Request,
    background_tasks: BackgroundTasks,
    project: ProjectIngestDep,
    db: DatabaseDep,
) -> SBOMIngestResponse:
    """Upload an SBOM for analysis; the analysis is queued and processed by background workers."""
    data = await read_json_body(request, SBOMIngest)
    manager = ScanManager(db, project)

    if not data.sboms:
        raise HTTPException(status_code=400, detail="No SBOM provided")

    scan_id = manager.run_scan_id(data)
    sbom_refs = await _upload_recognized_sboms(data.sboms, db, scan_id)
    if not sbom_refs:
        raise HTTPException(
            status_code=400,
            detail=f"None of the {len(data.sboms)} document(s) is a CycloneDX, SPDX or Syft SBOM.",
        )
    sboms_processed = len(sbom_refs)
    sboms_failed = len(data.sboms) - sboms_processed

    scan_update = await manager.record_release_and_build_scan_upsert(data, scan_id, datetime.now(timezone.utc))
    # Replace (never append) so a CI retry cannot pile up duplicate SBOMs that get
    # stored and re-analysed forever; the orphan reaper frees the superseded uploads.
    scan_update["$set"]["sbom_refs"] = sbom_refs
    scan_update["$inc"] = {"sbom_generation": 1}
    await db.scans.update_one({"_id": scan_id}, scan_update, upsert=True)
    await ScanRepository(db).reopen_finished(scan_id, statuses=[*SCAN_USABLE_STATUSES, SCAN_STATUS_FAILED])
    await manager.register_result(scan_id, "sbom", trigger_analysis=True)

    background_tasks.add_task(
        webhook_service.safe_trigger_webhooks,
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
        },
        str(project.id),
        context="sbom_ingest",
    )

    background_tasks.add_task(
        safe_notify_project_event,
        db,
        project_id=str(project.id),
        event_type=NOTIFICATION_EVENT_SBOM_INGESTED,
        subject=f"SBOM ingested: {project.name}",
        message=f"{sboms_processed} SBOM(s) ingested for project {project.name}.",
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
        project_id=str(project.id),
        active_analyzers=project.active_analyzers,
        retention_days=project.retention_days,
    )
