"""
/api/v1/ingest/cbom

Accepts CycloneDX 1.6 CBOM payloads (or any CycloneDX SBOM whose components
include ``type: cryptographic-asset`` entries).  Creates a scan record and
persists CryptoAssets via CryptoAssetRepository.

Authentication follows the same ``get_project_for_ingest`` dependency used by
all other ingest endpoints — the project is resolved from the API key (or OIDC
Job-Token) attached to the request.  No ``project_name`` lookup is required.
"""

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict

from fastapi import BackgroundTasks, Depends, HTTPException, status
from pydantic import BaseModel, Field

from app.api.deps import DatabaseDep
from app.api import deps
from app.api.router import CustomAPIRouter
from app.core.constants import WEBHOOK_EVENT_CRYPTO_ASSET_INGESTED
from app.models.crypto_asset import CryptoAsset
from app.models.project import Project
from app.repositories.crypto_asset import CryptoAssetRepository
from app.repositories.scans import ScanRepository
from app.services.cbom_parser import parse_cbom
from app.services.webhooks import webhook_service

logger = logging.getLogger(__name__)

router = CustomAPIRouter()

MAX_CRYPTO_ASSETS_PER_SCAN = 50_000

# The same annotated dep used by every other ingest endpoint
ProjectIngestDep = deps.get_project_for_ingest


class CBOMIngestPayload(BaseModel):
    scan_metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Optional CI/CD context (git_ref, commit_sha, etc.)",
    )
    cbom: Dict[str, Any] = Field(..., description="CycloneDX CBOM payload")


class CBOMIngestResponse(BaseModel):
    scan_id: str
    status: str


@router.post(
    "/ingest/cbom",
    response_model=CBOMIngestResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Ingest CBOM",
    tags=["cbom-ingest"],
)
async def ingest_cbom(
    payload: CBOMIngestPayload,
    background_tasks: BackgroundTasks,
    db: DatabaseDep,
    project: Project = Depends(ProjectIngestDep),
) -> CBOMIngestResponse:
    """
    Upload a CBOM for a project.

    Requires a valid **API Key** in the ``X-API-Key`` header (or an OIDC
    Job-Token).  The project is resolved from that credential — the same
    mechanism used by all other ``/ingest/*`` endpoints.

    The payload is parsed synchronously; assets are persisted in a
    background task so the response is returned quickly.
    """
    parsed = parse_cbom(payload.cbom)

    if parsed.parsed_components == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No cryptographic-asset components found in CBOM payload",
        )

    scan_id = str(uuid.uuid4())
    project_id = str(project.id)
    now = datetime.now(timezone.utc)

    # Create the scan document upfront so the background task can update it
    scan_update: Dict[str, Any] = {
        "$setOnInsert": {
            "_id": scan_id,
            "project_id": project_id,
            "scan_type": "cbom",
            "status": "pending",
            "branch": payload.scan_metadata.get("git_ref", "unknown"),
            "commit_hash": payload.scan_metadata.get("commit_sha"),
            "sbom_refs": [],
            "created_at": now,
        },
        "$set": {
            "updated_at": now,
            **{k: v for k, v in payload.scan_metadata.items() if k not in ("git_ref", "commit_sha")},
        },
    }

    scan_repo = ScanRepository(db)
    await scan_repo.upsert({"_id": scan_id}, scan_update)

    background_tasks.add_task(
        _persist_crypto_assets,
        db,
        project_id,
        scan_id,
        parsed,
    )

    return CBOMIngestResponse(scan_id=scan_id, status="accepted")


async def _persist_crypto_assets(db, project_id: str, scan_id: str, parsed) -> None:
    """Background task: bulk-upsert CryptoAsset records then dispatch analysis."""
    from app.core.worker import worker_manager

    scan_repo = ScanRepository(db)
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
            "cbom_ingest: persisted %d assets for scan %s%s; queuing analysis",
            len(crypto_assets),
            scan_id,
            " (partial)" if partial else "",
        )

        # Fire crypto_asset.ingested webhook (best-effort; never blocks ingest)
        try:
            summary = await CryptoAssetRepository(db).summary_for_scan(project_id, scan_id)
            await webhook_service.trigger_webhooks(
                db,
                WEBHOOK_EVENT_CRYPTO_ASSET_INGESTED,
                {
                    "scan_id": scan_id,
                    "project_id": project_id,
                    "total": summary["total"],
                    "by_type": summary["by_type"],
                },
                project_id,
            )
        except Exception as exc:
            logger.warning(
                "cbom_ingest: webhook dispatch failed for scan %s (non-fatal): %s",
                scan_id,
                exc,
            )

        # Keep status as "pending" and hand the scan to the analysis worker so
        # the crypto analyzers run via the standard engine dispatch path.
        # The engine marks the scan "completed" (or "failed") when done.
        queued = await worker_manager.add_job(scan_id)
        if not queued:
            # Worker is shutting down — mark the scan so housekeeping re-queues it.
            logger.warning(
                "cbom_ingest: worker rejected job for scan %s (shutting down); scan remains pending for recovery",
                scan_id,
            )

    except Exception as exc:
        logger.exception("cbom_ingest background task failed for scan %s: %s", scan_id, exc)
        await scan_repo.update_raw(scan_id, {"$set": {"status": "failed"}})
