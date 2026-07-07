"""Ingest CycloneDX 1.6 CBOM payloads; creates a scan and persists CryptoAssets."""

import logging
from typing import Any, Dict, Optional

from fastapi import BackgroundTasks, Depends, HTTPException, Request, status
from motor.motor_asyncio import AsyncIOMotorDatabase
from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.api.deps import DatabaseDep
from app.api import deps
from app.api.router import CustomAPIRouter
from app.core.constants import MAX_CBOM_BODY_BYTES, MAX_CRYPTO_ASSETS_PER_SCAN, WEBHOOK_EVENT_CRYPTO_ASSET_INGESTED
from app.core.metrics import cbom_ingests_total
from app.models.crypto_asset import CryptoAsset
from app.models.project import Project
from app.repositories.crypto_asset import CryptoAssetRepository
from app.schemas.ingest import BaseIngest
from app.services.cbom_parser import ParsedCBOM, parse_cbom
from app.services.notifications.service import safe_notify_project_event
from app.services.scan_manager import ScanManager
from app.services.webhooks import webhook_service

logger = logging.getLogger(__name__)

router = CustomAPIRouter()

ProjectIngestDep = deps.get_project_for_ingest


def _enforce_body_size_limit(request: Request) -> None:
    """Reject oversized CBOM uploads before Pydantic parses them."""
    raw = request.headers.get("content-length")
    if raw is None:
        return
    try:
        size = int(raw)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid Content-Length header")
    if size > MAX_CBOM_BODY_BYTES:
        raise HTTPException(
            status_code=413,
            detail=(
                f"CBOM payload exceeds {MAX_CBOM_BODY_BYTES} bytes "
                f"({size} bytes received). Split the upload or raise the limit."
            ),
        )


class CBOMIngest(BaseIngest):
    """CBOM ingest payload; flat shape aligned with SBOMIngest, also accepting a legacy scan_metadata envelope."""

    cbom: Dict[str, Any] = Field(..., description="CycloneDX 1.6 CBOM payload")

    # Optional so legacy payloads without pipeline_id/commit_hash/branch can still ingest.
    pipeline_id: Optional[int] = Field(None, description="Unique ID of the pipeline run")  # type: ignore[assignment]
    commit_hash: Optional[str] = Field(None, description="Git commit hash")  # type: ignore[assignment]
    branch: Optional[str] = Field(None, description="Git branch name")  # type: ignore[assignment]

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


@router.post(
    "/ingest/cbom",
    response_model=CBOMIngestResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Ingest CBOM",
    tags=["cbom-ingest"],
    dependencies=[Depends(_enforce_body_size_limit)],
)
async def ingest_cbom(
    payload: CBOMIngest,
    background_tasks: BackgroundTasks,
    db: DatabaseDep,
    project: Project = Depends(ProjectIngestDep),
) -> CBOMIngestResponse:
    """Upload a CBOM for a project; parsed synchronously, assets persisted in a background task."""
    parsed = parse_cbom(payload.cbom)

    if parsed.parsed_components == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No cryptographic-asset components found in CBOM payload",
        )

    # Route through ScanManager so the scan lifecycle matches other ingest paths.
    manager = ScanManager(db, project)
    scan_ctx = await manager.find_or_create_scan(payload)
    scan_id = scan_ctx.scan_id

    # Tag as CBOM so the analysis engine forces crypto analyzers even without an SBOM.
    from app.repositories.scans import ScanRepository

    await ScanRepository(db).update_raw(scan_id, {"$set": {"scan_type": "cbom"}})

    background_tasks.add_task(
        _persist_crypto_assets,
        db,
        project,
        scan_id,
        parsed,
    )

    return CBOMIngestResponse(scan_id=scan_id, status="accepted")


async def _persist_crypto_assets(
    db: AsyncIOMotorDatabase,
    project: Project,
    scan_id: str,
    parsed: ParsedCBOM,
) -> None:
    """Bulk-upsert CryptoAsset records then register the scan result via ScanManager."""
    manager = ScanManager(db, project)
    project_id = str(project.id)
    try:
        assets = parsed.assets
        partial = False
        if len(assets) > MAX_CRYPTO_ASSETS_PER_SCAN:
            assets = assets[:MAX_CRYPTO_ASSETS_PER_SCAN]
            partial = True
            logger.warning(
                "cbom_ingest: truncated to %d assets for scan %s",
                MAX_CRYPTO_ASSETS_PER_SCAN,
                scan_id,
            )

        crypto_assets = [
            CryptoAsset(
                project_id=project_id,
                scan_id=scan_id,
                **a.model_dump(),
            )
            for a in assets
        ]

        await CryptoAssetRepository(db).bulk_upsert(project_id, scan_id, crypto_assets)

        logger.info(
            "cbom_ingest: persisted %d assets for scan %s%s; registering result",
            len(crypto_assets),
            scan_id,
            " (partial)" if partial else "",
        )

        # Fire ingest webhook (best-effort).
        summary = await CryptoAssetRepository(db).summary_for_scan(project_id, scan_id)
        await webhook_service.safe_trigger_webhooks(
            db,
            WEBHOOK_EVENT_CRYPTO_ASSET_INGESTED,
            {
                "scan_id": scan_id,
                "project_id": project_id,
                "total": summary["total"],
                "by_type": summary["by_type"],
            },
            project_id,
            context="cbom_ingest",
        )

        await safe_notify_project_event(
            db,
            project_id=project_id,
            event_type="crypto_asset_ingested",
            subject=f"Crypto assets ingested: {summary['total']} entries",
            message=f"{summary['total']} crypto asset(s) ingested for scan {scan_id}.",
            context="cbom_ingest",
        )

        await manager.register_result(scan_id, "cbom", trigger_analysis=True)
        cbom_ingests_total.labels(status="success").inc()

    except Exception as exc:
        logger.exception("cbom_ingest background task failed for scan %s: %s", scan_id, exc)
        cbom_ingests_total.labels(status="error").inc()
        from app.repositories.scans import ScanRepository

        scan_repo = ScanRepository(db)
        await scan_repo.update_raw(scan_id, {"$set": {"status": "failed"}})
