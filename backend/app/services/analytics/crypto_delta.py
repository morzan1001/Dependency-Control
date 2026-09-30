"""Crypto-delta: match crypto assets across two scans by ``(name, variant, primitive)``
(``bom_ref`` is regenerated per scan and unusable for matching), as a ScanDeltaResponse.
"""

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.core.constants import MAX_CRYPTO_ASSETS_PER_SCAN
from app.models.crypto_asset import CryptoAsset
from app.repositories.crypto_asset import CryptoAssetRepository
from app.schemas.scan_delta import (
    CryptoDeltaItem,
    DeltaCategory,
    ScanDeltaResponse,
    ScanDeltaTotals,
)
from app.services.analytics._delta_pagination import by_side, delta_truncation, paginate
from app.services.analytics._delta_reachability import side_reachability


def _key(asset: CryptoAsset) -> tuple[str, str, str]:
    """Semantic identity used for cross-scan matching."""
    return (
        asset.name or "",
        asset.variant or "",
        asset.primitive or "",
    )


def _group_to_envelope_item(group: list[CryptoAsset], change: str) -> CryptoDeltaItem:
    return CryptoDeltaItem(
        change=change,
        name=group[0].name or "",
        variant=group[0].variant,
        primitive=group[0].primitive,
        locations=sorted({loc for asset in group for loc in asset.occurrence_locations or []}),
        asset_count=len(group),
    )


async def _side_assets(
    repo: CryptoAssetRepository,
    project_id: str,
    scan_id: str,
) -> tuple[list[CryptoAsset], int]:
    """The side's assets and how many it holds. ``list_by_scan`` orders by name, so a capped side
    is cut at the same alphabetical point on both sides."""
    assets = await repo.list_by_scan(project_id, scan_id, limit=MAX_CRYPTO_ASSETS_PER_SCAN)
    if len(assets) < MAX_CRYPTO_ASSETS_PER_SCAN:
        return assets, len(assets)
    return assets, await repo.count_by_scan(project_id, scan_id)


async def compute_crypto_delta_envelope(
    db: AsyncIOMotorDatabase,
    *,
    project_id: str,
    from_scan: str,
    to_scan: str,
    page: int,
    page_size: int,
    change: str | None,
) -> ScanDeltaResponse:
    repo = CryptoAssetRepository(db)
    from_assets, from_total = await _side_assets(repo, project_id, from_scan)
    to_assets, to_total = await _side_assets(repo, project_id, to_scan)

    groups = list(by_side(_key, from_assets, to_assets).values())
    added = [new for gone, new in groups if not gone]
    removed = [gone for gone, new in groups if not new]

    items: list[CryptoDeltaItem] = []
    if change in (None, "all", "added"):
        items.extend(_group_to_envelope_item(group, "added") for group in added)
    if change in (None, "all", "removed"):
        items.extend(_group_to_envelope_item(group, "removed") for group in removed)

    # Sort with variant/primitive tiebreakers so pagination does not depend on fetch order.
    items.sort(key=lambda i: (i.change, i.name, i.variant or "", i.primitive or ""))
    paged, total_pages = paginate(items, page, page_size)

    return ScanDeltaResponse(
        from_scan_id=from_scan,
        to_scan_id=to_scan,
        project_id=project_id,
        category=DeltaCategory.CRYPTO,
        totals=ScanDeltaTotals(
            added=len(added),
            removed=len(removed),
            unchanged=len(groups) - len(added) - len(removed),
        ),
        page=page,
        page_size=page_size,
        total_pages=total_pages,
        items=paged,
        from_reachability=await side_reachability(db, from_scan),
        to_reachability=await side_reachability(db, to_scan),
        truncation=delta_truncation(
            MAX_CRYPTO_ASSETS_PER_SCAN,
            from_compared=len(from_assets),
            from_total=from_total,
            to_compared=len(to_assets),
            to_total=to_total,
        ),
    )
