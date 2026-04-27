"""
/api/v1/ingest/cbom

Accepts CycloneDX 1.6 CBOM payloads (or any CycloneDX SBOM whose components
include ``type: cryptographic-asset`` entries).  Creates a scan record via
``ScanManager`` and persists CryptoAssets via ``CryptoAssetRepository``.

Authentication follows the same ``get_project_for_ingest`` dependency used by
all other ingest endpoints — the project is resolved from the API key (or OIDC
Job-Token) attached to the request.  No ``project_name`` lookup is required.
"""

import logging
from typing import Any, Dict, Optional

from fastapi import BackgroundTasks, Depends, HTTPException, status
from motor.motor_asyncio import AsyncIOMotorDatabase
from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.api.deps import DatabaseDep
from app.api import deps
from app.api.router import CustomAPIRouter
from app.core.constants import WEBHOOK_EVENT_CRYPTO_ASSET_INGESTED
from app.models.crypto_asset import CryptoAsset
from app.models.project import Project
from app.repositories.crypto_asset import CryptoAssetRepository
from app.schemas.ingest import BaseIngest
from app.services.cbom_parser import ParsedCBOM, parse_cbom
from app.services.scan_manager import ScanManager
from app.services.webhooks import webhook_service

logger = logging.getLogger(__name__)

router = CustomAPIRouter()

MAX_CRYPTO_ASSETS_PER_SCAN = 50_000

ProjectIngestDep = deps.get_project_for_ingest


class CBOMIngest(BaseIngest):
    """CBOM ingest payload — flat shape aligned with SBOMIngest.

    The canonical payload places the CycloneDX CBOM content under the
    top-level ``cbom`` field and all CI metadata (pipeline_id, commit_hash,
    branch, job_id, ...) as direct BaseIngest fields, exactly like
    SBOMIngest. This mirrors the pipeline-template cboms.yml output.

    For backward-compatibility with older clients, a nested
    ``{"scan_metadata": {...}, "cbom": {...}}`` envelope is also accepted.
    ``scan_metadata.git_ref`` maps to ``branch`` and
    ``scan_metadata.commit_sha`` maps to ``commit_hash`` when the canonical
    fields are absent.
    """

    cbom: Dict[str, Any] = Field(..., description="CycloneDX 1.6 CBOM payload")

    # Loosen BaseIngest's required fields so legacy payloads without
    # pipeline_id/commit_hash/branch can still ingest.
    pipeline_id: Optional[int] = Field(None, description="Unique ID of the pipeline run")  # type: ignore[assignment]
    commit_hash: Optional[str] = Field(None, description="Git commit hash")  # type: ignore[assignment]
    branch: Optional[str] = Field(None, description="Git branch name")  # type: ignore[assignment]

    # Accept unknown keys without validation errors (e.g. scan_metadata from
    # legacy clients) and let the pre-validator fold them into the canonical
    # fields.
    model_config = ConfigDict(extra="allow")

    @model_validator(mode="before")
    @classmethod
    def _fold_legacy_scan_metadata(cls, values: Any) -> Any:
        """If a legacy ``scan_metadata`` envelope is present, fold its
        fields onto the top-level payload so canonical validation picks
        them up."""
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
)
async def ingest_cbom(
    payload: CBOMIngest,
    background_tasks: BackgroundTasks,
    db: DatabaseDep,
    project: Project = Depends(ProjectIngestDep),
) -> CBOMIngestResponse:
    """Upload a CBOM for a project.

    Requires a valid **API Key** in the ``X-API-Key`` header (or an OIDC
    Job-Token).  The project is resolved from that credential — the same
    mechanism used by all other ``/ingest/*`` endpoints.

    The payload is parsed synchronously; assets are persisted in a
    background task so the response is returned quickly.

    Scan lifecycle is managed by ``ScanManager``: the scan_id is derived
    deterministically from (project, pipeline_id, commit_hash) so that
    re-submission of the same CI run upserts instead of creating a
    duplicate scan.
    """
    parsed = parse_cbom(payload.cbom)

    if parsed.parsed_components == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No cryptographic-asset components found in CBOM payload",
        )

    # Route through ScanManager so the scan lifecycle (deterministic
    # scan_id, CI metadata persistence, register_result -> analysis
    # trigger) matches SBOM and other ingest paths exactly.
    manager = ScanManager(db, project)
    scan_ctx = await manager.find_or_create_scan(payload)
    scan_id = scan_ctx.scan_id

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
    """Background task: bulk-upsert CryptoAsset records then register
    the scan result via ScanManager (which queues the analysis worker)."""
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

        # Fire crypto_asset.ingested webhook (best-effort; never blocks ingest)
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

        # Register the CBOM result on the scan and trigger the aggregation
        # worker — identical flow to SBOM ingest (register_result with
        # trigger_analysis=True).  The analysis engine marks the scan
        # completed/failed when the crypto analyzers finish.
        await manager.register_result(scan_id, "cbom", trigger_analysis=True)

    except Exception as exc:
        logger.exception("cbom_ingest background task failed for scan %s: %s", scan_id, exc)
        from app.repositories.scans import ScanRepository

        scan_repo = ScanRepository(db)
        await scan_repo.update_raw(scan_id, {"$set": {"status": "failed"}})
