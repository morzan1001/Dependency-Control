"""Ingest CycloneDX 1.6 CBOM payloads; creates a scan and persists CryptoAssets."""

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any

from fastapi import HTTPException, Request, status
from motor.motor_asyncio import AsyncIOMotorDatabase
from pydantic import BaseModel, ConfigDict, Field, model_validator

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
from app.schemas.ingest import BaseIngest
from app.services.cbom_parser import ParsedCBOM, parse_cbom
from app.services.notifications.service import safe_notify_project_event
from app.services.scan_manager import ScanManager
from app.services.webhooks import webhook_service

logger = logging.getLogger(__name__)

router = CustomAPIRouter()


class CBOMIngest(BaseIngest):
    """CBOM ingest payload; flat shape aligned with SBOMIngest, also accepting a legacy scan_metadata envelope."""

    cbom: dict[str, Any] = Field(..., description="CycloneDX 1.6 CBOM payload")

    # Optional so legacy payloads without pipeline_id/commit_hash/branch can still ingest.
    pipeline_id: int | None = Field(None, description="Unique ID of the pipeline run")  # type: ignore[assignment]
    commit_hash: str | None = Field(None, description="Git commit hash")  # type: ignore[assignment]
    branch: str | None = Field(None, description="Git branch name")  # type: ignore[assignment]

    # Accept unknown keys so the pre-validator can fold a legacy scan_metadata envelope.
    model_config = ConfigDict(extra="allow")

    @model_validator(mode="before")
    @classmethod
    def _fold_legacy_scan_metadata(cls, values: Any) -> Any:
        """Fold a legacy scan_metadata envelope onto the top-level payload for canonical validation."""
        if not isinstance(values, dict):
            return values
        meta = values.get("scan_metadata")
        if not isinstance(meta, dict):
            return values
        # Only fill fields that are not already present on the envelope.
        mappings = {
            "branch": meta.get("git_ref") or meta.get("branch"),
            "commit_hash": meta.get("commit_sha") or meta.get("commit_hash"),
            "pipeline_id": meta.get("pipeline_id"),
            "pipeline_iid": meta.get("pipeline_iid"),
            "project_url": meta.get("project_url"),
            "pipeline_url": meta.get("pipeline_url"),
            "job_id": meta.get("job_id"),
            "job_started_at": meta.get("job_started_at"),
            "commit_message": meta.get("commit_message"),
            "commit_tag": meta.get("commit_tag"),
            "project_name": meta.get("project_name"),
            "pipeline_user": meta.get("pipeline_user"),
        }
        for key, value in mappings.items():
            if value is not None and values.get(key) is None:
                values[key] = value
        return values


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
    db: DatabaseDep,
    project: ProjectIngestDep,
) -> CBOMIngestResponse:
    """Upload a CBOM for a project; parsed and persisted synchronously so nothing is lost after the response."""
    payload = await read_json_body(request, CBOMIngest)
    manager = ScanManager(db, project)
    scan_id = manager.run_scan_id(payload)
    parsed = await asyncio.to_thread(parse_cbom, payload.cbom)

    if parsed.parsed_components == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No cryptographic-asset components found in CBOM payload",
        )

    project_id = str(project.id)

    try:
        summary = await _store_crypto_assets(db, project_id, scan_id, parsed)
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

    await webhook_service.safe_trigger_webhooks(
        db,
        WEBHOOK_EVENT_CRYPTO_ASSET_INGESTED,
        {"scan_id": scan_id, "project_id": project_id, "total": summary["total"], "by_type": summary["by_type"]},
        project_id,
        context="cbom_ingest",
    )
    await safe_notify_project_event(
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
        assets_received=len(parsed.assets),
        assets_stored=int(summary["total"]),
    )


async def _store_crypto_assets(
    db: AsyncIOMotorDatabase, project_id: str, scan_id: str, parsed: ParsedCBOM
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
            for a in parsed.assets
        ),
    )
    # Deleted after the upsert so a failed write keeps the previous upload's assets.
    await repo.delete_older_writes({"project_id": project_id, "scan_id": scan_id, "cbom_upload": True}, written_at)
    # Counts persisted docs, so duplicate bom_refs in one payload are reported honestly
    # (bulk_upsert returns submitted ops, which always equals the input length).
    summary: dict[str, Any] = await repo.summary_for_scan(project_id, scan_id)
    logger.info("cbom_ingest: persisted %d assets for scan %s", summary["total"], scan_id)
    return summary
