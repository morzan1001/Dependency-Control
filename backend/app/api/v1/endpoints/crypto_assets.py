"""Read-only endpoints for crypto assets."""

from typing import Any, Optional

from fastapi import HTTPException, Query

from app.api.router import CustomAPIRouter
from app.api.v1.helpers.projects import check_project_access
from app.api.deps import CurrentUserDep, DatabaseDep
from app.repositories.crypto_asset import CryptoAssetRepository
from app.schemas.cbom import CryptoAssetType, CryptoPrimitive

router = CustomAPIRouter(tags=["crypto-assets"])


@router.get("/projects/{project_id}/crypto-assets")
async def list_crypto_assets(
    project_id: str,
    current_user: CurrentUserDep,
    db: DatabaseDep,
    scan_id: str = Query(..., description="Scan ID to list assets for"),
    asset_type: Optional[CryptoAssetType] = Query(None),
    primitive: Optional[CryptoPrimitive] = Query(None),
    name_search: Optional[str] = Query(None),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
) -> dict[str, Any]:
    """List crypto assets for a scan with pagination and optional filtering."""
    # Check project access
    await check_project_access(project_id, current_user, db, required_role="viewer")

    repo = CryptoAssetRepository(db)
    items = await repo.list_by_scan(
        project_id,
        scan_id,
        limit=limit,
        skip=skip,
        asset_type=asset_type,
        primitive=primitive,
        name_search=name_search,
    )
    total = await repo.count_by_scan(project_id, scan_id)
    return {
        "items": [i.model_dump(by_alias=True) for i in items],
        "total": total,
        "limit": limit,
        "skip": skip,
    }


@router.get("/projects/{project_id}/crypto-assets/{asset_id}")
async def get_crypto_asset(
    project_id: str,
    asset_id: str,
    current_user: CurrentUserDep,
    db: DatabaseDep,
) -> dict[str, Any]:
    """Get a single crypto asset by ID."""
    # Check project access
    await check_project_access(project_id, current_user, db, required_role="viewer")

    asset = await CryptoAssetRepository(db).get(project_id, asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="CryptoAsset not found")
    return asset.model_dump(by_alias=True)


@router.get("/projects/{project_id}/scans/{scan_id}/crypto-assets/summary")
async def crypto_assets_summary(
    project_id: str,
    scan_id: str,
    current_user: CurrentUserDep,
    db: DatabaseDep,
) -> dict[str, Any]:
    """Get a summary of crypto assets for a scan, grouped by type."""
    # Check project access
    await check_project_access(project_id, current_user, db, required_role="viewer")

    return await CryptoAssetRepository(db).summary_for_scan(project_id, scan_id)
