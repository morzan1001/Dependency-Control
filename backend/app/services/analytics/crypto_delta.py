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
from app.services.analytics._delta_pagination import delta_truncation, paginate
from app.services.analytics._delta_reachability import side_reachability


def _primitive_str(asset: CryptoAsset) -> str | None:
    """Stringify ``asset.primitive`` whether it's an enum, string, or None."""
    primitive = asset.primitive
    if primitive is None:
        return None
    if hasattr(primitive, "value"):
        return primitive.value
    return str(primitive)


def _key(asset: CryptoAsset) -> tuple[str, str, str]:
    """Semantic identity used for cross-scan matching."""
    return (
        asset.name or "",
        asset.variant or "",
        _primitive_str(asset) or "",
    )


def _asset_to_envelope_item(asset: CryptoAsset, change: str) -> CryptoDeltaItem:
    return CryptoDeltaItem(
        change=change,
        name=asset.name or "",
        variant=asset.variant,
        primitive=_primitive_str(asset),
        locations=list(asset.occurrence_locations or []),
        asset_count=1,
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

    from_map = {_key(a): a for a in from_assets}
    to_map = {_key(a): a for a in to_assets}

    added_keys = to_map.keys() - from_map.keys()
    removed_keys = from_map.keys() - to_map.keys()
    unchanged = len(to_map.keys() & from_map.keys())

    items: list[CryptoDeltaItem] = []
    if change in (None, "all", "added"):
        items.extend(_asset_to_envelope_item(to_map[k], "added") for k in added_keys)
    if change in (None, "all", "removed"):
        items.extend(_asset_to_envelope_item(from_map[k], "removed") for k in removed_keys)

    # Sort with variant/primitive tiebreakers so pagination is deterministic across set-iteration order.
    items.sort(key=lambda i: (i.change, i.name, i.variant or "", i.primitive or ""))
    paged, total_pages = paginate(items, page, page_size)

    return ScanDeltaResponse(
        from_scan_id=from_scan,
        to_scan_id=to_scan,
        project_id=project_id,
        category=DeltaCategory.CRYPTO,
        totals=ScanDeltaTotals(
            added=len(added_keys),
            removed=len(removed_keys),
            unchanged=unchanged,
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
