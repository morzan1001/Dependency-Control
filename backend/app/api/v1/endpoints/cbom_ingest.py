import asyncio
import logging
from datetime import datetime, timezone
from typing import Any

from fastapi import BackgroundTasks, HTTPException, Request, status
from motor.motor_asyncio import AsyncIOMotorDatabase
from pydantic import BaseModel

from app.api.deps import DatabaseDep, ProjectIngestDep
from app.api.router import CustomAPIRouter
from app.api.v1.helpers.request_body import read_json_body
from app.api.v1.helpers.responses import RESP_AUTH_400_409_500
from app.core.constants import (
    NOTIFICATION_EVENT_CRYPTO_ASSET_INGESTED,
    SCAN_TYPE_CBOM,
    WEBHOOK_EVENT_CRYPTO_ASSET_INGESTED,
)
from app.core.metrics import cbom_ingests_total
from app.repositories.crypto_asset import CryptoAssetRepository
from app.repositories.scans import ScanRepository
from app.schemas.cbom import CBOMIngest, ParsedCryptoAsset
from app.services.analysis.runner import sbom_name
from app.services.cbom_parser import flatten_cyclonedx_components, parse_cbom
from app.services.notifications.service import safe_notify_project_event
from app.services.scan_manager import ScanManager
from app.services.webhooks import webhook_service

logger = logging.getLogger(__name__)

router = CustomAPIRouter()


class CBOMIngestResponse(BaseModel):
    scan_id: str
    status: str
    assets_received: int
    assets_stored: int


@router.post(
    "/ingest/cbom",
    status_code=status.HTTP_202_ACCEPTED,
    summary="Ingest CBOM",
    responses=RESP_AUTH_400_409_500,
)
async def ingest_cbom(
    request: Request,
    background_tasks: BackgroundTasks,
    db: DatabaseDep,
    project: ProjectIngestDep,
) -> CBOMIngestResponse:
    """Upload a CBOM, persisted before the response; one listing no crypto asset records the project as free of crypto."""
    payload = await read_json_body(request, CBOMIngest)
    manager = ScanManager(db, project)
    scan_id = manager.run_scan_id(payload)
    assets = await asyncio.to_thread(parse_cbom, payload.cbom)
    if not assets and payload.cbom.get("bomFormat") != "CycloneDX":
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "CBOM payload is not a CycloneDX document")
    components = payload.cbom.get("components", [])
    if not assets and (
        not isinstance(components, list)
        or any(c.get("type") == "cryptographic-asset" for c in flatten_cyclonedx_components(components)[0])
    ):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "CBOM components could not be read as cryptographic assets")
    project_id = str(project.id)

    await manager.refuse_while_restoring(scan_id)
    try:
        await ScanRepository(db).touch(scan_id)
        summary = await _store_crypto_assets(db, project_id, scan_id, assets, _cbom_source(payload))
    except Exception as exc:
        logger.exception("cbom_ingest failed for scan %s: %s", scan_id, exc)
        cbom_ingests_total.labels(status="error").inc()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to persist crypto assets. Please retry the upload.",
        ) from exc

    # The cbom tag makes the analysis engine run the crypto analyzers even without an SBOM.
    await manager.find_or_create_scan(payload, scan_id, scan_type=SCAN_TYPE_CBOM)
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
    cbom_ingests_total.labels(status="success" if assets else "empty").inc()

    return CBOMIngestResponse(
        scan_id=scan_id,
        status="accepted",
        assets_received=len(assets),
        assets_stored=int(summary["total"]),
    )


def _cbom_source(payload: CBOMIngest) -> str | None:
    """A retried job regenerates its CBOM under a new serialNumber; its job name, tools and target stay."""
    cbom = payload.cbom
    if not payload.job_name:
        serial = cbom.get("serialNumber")
        return str(serial) if serial else sbom_name(cbom)
    metadata = cbom.get("metadata")
    metadata = metadata if isinstance(metadata, dict) else {}
    tools = metadata.get("tools")
    # CycloneDX 1.5 nests the tools under "components"; 1.4 lists them directly.
    tools = tools.get("components") if isinstance(tools, dict) else tools
    tool_names = (
        sorted({str(t["name"]) for t in tools if isinstance(t, dict) and t.get("name")})
        if isinstance(tools, list)
        else []
    )
    target = metadata.get("component")
    target_name = target.get("name") if isinstance(target, dict) else None
    return "\n".join([payload.job_name, *tool_names, str(target_name or "")])


async def _store_crypto_assets(
    db: AsyncIOMotorDatabase, project_id: str, scan_id: str, assets: list[ParsedCryptoAsset], source: str | None
) -> dict[str, Any]:
    """The CBOMs of one pipeline run add up; a retried one replaces its own earlier assets."""
    written_at = datetime.now(timezone.utc)
    repo = CryptoAssetRepository(db)
    summary = await repo.store_parsed(
        project_id, scan_id, assets, cbom_upload=True, created_at=written_at, cbom_source=source
    )
    # Deleted after the upsert so a failed write keeps the previous upload's assets.
    await repo.delete_older_writes(
        {"project_id": project_id, "scan_id": scan_id, "cbom_upload": True, "cbom_source": source}, written_at
    )
    logger.info("cbom_ingest: persisted %d assets for scan %s", summary["total"], scan_id)
    return summary
