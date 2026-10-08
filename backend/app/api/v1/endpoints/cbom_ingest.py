"""Ingest CycloneDX 1.6 CBOM payloads; creates a scan and persists CryptoAssets."""

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any

from fastapi import BackgroundTasks, HTTPException, Request, status
from motor.motor_asyncio import AsyncIOMotorDatabase
from pydantic import BaseModel, Field

from app.api.deps import DatabaseDep, ProjectIngestDep
from app.api.router import CustomAPIRouter
from app.api.v1.helpers.request_body import read_json_body
from app.core.constants import (
    NOTIFICATION_EVENT_CRYPTO_ASSET_INGESTED,
    WEBHOOK_EVENT_CRYPTO_ASSET_INGESTED,
)
from app.core.metrics import cbom_ingests_total
from app.models.crypto_asset import CryptoAsset
from app.repositories.crypto_asset import CryptoAssetRepository
from app.repositories.scans import ScanRepository
from app.schemas.cbom import ParsedCryptoAsset
from app.schemas.ingest import BaseIngest
from app.services.cbom_parser import parse_cbom
from app.services.notifications.service import safe_notify_project_event
from app.services.scan_manager import ScanManager
from app.services.webhooks import webhook_service

logger = logging.getLogger(__name__)

router = CustomAPIRouter()


class CBOMIngest(BaseIngest):
    """CBOM ingest payload; flat shape aligned with SBOMIngest."""

    cbom: dict[str, Any] = Field(..., description="CycloneDX 1.6 CBOM payload")

    # Optional so an upload without pipeline metadata still ingests.
    pipeline_id: int | None = Field(None, description="Unique ID of the pipeline run")  # type: ignore[assignment]
    commit_hash: str | None = Field(None, description="Git commit hash")  # type: ignore[assignment]
    branch: str | None = Field(None, description="Git branch name")  # type: ignore[assignment]


class CBOMIngestResponse(BaseModel):
    scan_id: str
    status: str
    assets_received: int
    assets_stored: int


@router.post(
    "/ingest/cbom",
    status_code=status.HTTP_202_ACCEPTED,
    summary="Ingest CBOM",
)
async def ingest_cbom(
    request: Request,
    background_tasks: BackgroundTasks,
    db: DatabaseDep,
    project: ProjectIngestDep,
) -> CBOMIngestResponse:
    """Upload a CBOM for a project; parsed and persisted synchronously so nothing is lost after the response."""
    payload = await read_json_body(request, CBOMIngest)
    manager = ScanManager(db, project)
    scan_id = manager.run_scan_id(payload)
    assets = await asyncio.to_thread(parse_cbom, payload.cbom)

    if not assets:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No cryptographic-asset components found in CBOM payload",
        )

    project_id = str(project.id)

    try:
        await ScanRepository(db).touch(scan_id)
        summary = await _store_crypto_assets(db, project_id, scan_id, assets)
    except Exception as exc:
        logger.exception("cbom_ingest failed for scan %s: %s", scan_id, exc)
        cbom_ingests_total.labels(status="error").inc()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to persist crypto assets. Please retry the upload.",
        ) from exc

    # The cbom tag makes the analysis engine run the crypto analyzers even without an SBOM.
    await manager.find_or_create_scan(payload, scan_id, scan_type="cbom")
    await manager.register_result(scan_id, "cbom", trigger_analysis=True)

    background_tasks.add_task(
        webhook_service.safe_trigger_webhooks,
        db,
        WEBHOOK_EVENT_CRYPTO_ASSET_INGESTED,
        {"scan_id": scan_id, "project_id": project_id, "total": summary["total"], "by_type": summary["by_type"]},
        project_id,
        context="cbom_ingest",
    )
    background_tasks.add_task(
        safe_notify_project_event,
        db,
        project_id=project_id,
        event_type=NOTIFICATION_EVENT_CRYPTO_ASSET_INGESTED,
        subject=f"Crypto assets ingested: {summary['total']} entries",
        message=f"{summary['total']} crypto asset(s) ingested for scan {scan_id}.",
        context="cbom_ingest",
    )
    cbom_ingests_total.labels(status="success").inc()

    return CBOMIngestResponse(
        scan_id=scan_id,
        status="accepted",
        assets_received=len(assets),
        assets_stored=int(summary["total"]),
    )


async def _store_crypto_assets(
    db: AsyncIOMotorDatabase, project_id: str, scan_id: str, assets: list[ParsedCryptoAsset]
) -> dict[str, Any]:
    """Bulk-upsert the scan's CryptoAssets and return the summary of what is stored."""
    written_at = datetime.now(timezone.utc)
    repo = CryptoAssetRepository(db)
    await repo.bulk_upsert(
        project_id,
        scan_id,
        (
            CryptoAsset(
                project_id=project_id, scan_id=scan_id, cbom_upload=True, created_at=written_at, **a.model_dump()
            )
            for a in assets
        ),
    )
    # Deleted after the upsert so a failed write keeps the previous upload's assets.
    await repo.delete_older_writes({"project_id": project_id, "scan_id": scan_id, "cbom_upload": True}, written_at)
    # Counts persisted docs, so duplicate bom_refs in one payload are reported honestly
    # (bulk_upsert returns submitted ops, which always equals the input length).
    summary: dict[str, Any] = await repo.summary_for_scan(project_id, scan_id)
    logger.info("cbom_ingest: persisted %d assets for scan %s", summary["total"], scan_id)
    return summary
