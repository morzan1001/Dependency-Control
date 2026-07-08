"""Crypto-delta: match crypto assets across two scans by ``(name, variant, primitive)``
(``bom_ref`` is regenerated per scan and unusable for matching), as a ScanDeltaResponse.
"""

from typing import List, Optional, Tuple

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.models.crypto_asset import CryptoAsset
from app.repositories.crypto_asset import CryptoAssetRepository
from app.schemas.scan_delta import (
    CryptoDeltaItem,
    DeltaCategory,
    ScanDeltaResponse,
    ScanDeltaTotals,
)
from app.services.analytics._delta_pagination import MAX_FETCH, paginate


def _primitive_str(asset: CryptoAsset) -> Optional[str]:
    """Stringify ``asset.primitive`` whether it's an enum, string, or None."""
    primitive = asset.primitive
    if primitive is None:
        return None
    if hasattr(primitive, "value"):
        return primitive.value
    return str(primitive)


def _key(asset: CryptoAsset) -> Tuple[str, str, str]:
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


async def compute_crypto_delta_envelope(
    db: AsyncIOMotorDatabase,
    *,
    project_id: str,
    from_scan: str,
    to_scan: str,
    page: int,
    page_size: int,
    change: Optional[str],
) -> ScanDeltaResponse:
    repo = CryptoAssetRepository(db)
    from_assets = await repo.list_by_scan(project_id, from_scan, limit=MAX_FETCH)
    to_assets = await repo.list_by_scan(project_id, to_scan, limit=MAX_FETCH)

    from_map = {_key(a): a for a in from_assets}
    to_map = {_key(a): a for a in to_assets}

    added_keys = to_map.keys() - from_map.keys()
    removed_keys = from_map.keys() - to_map.keys()
    unchanged = len(to_map.keys() & from_map.keys())

    items: List[CryptoDeltaItem] = []
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
    )
