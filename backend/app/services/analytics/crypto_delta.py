"""
Scan-delta computation.

Key tuple: (name, variant, primitive). bom_ref can drift between scans, so
we use the semantic identity of the crypto asset instead.
"""

from datetime import datetime, timezone
from typing import Optional, Tuple

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.models.crypto_asset import CryptoAsset
from app.repositories.crypto_asset import CryptoAssetRepository
from app.schemas.analytics import HotspotEntry, ScanDelta
from app.schemas.scan_delta import (
    CryptoDeltaItem,
    DeltaCategory,
    ScanDeltaResponse,
    ScanDeltaTotals,
)


def _key(asset: CryptoAsset) -> Tuple[str, str, str]:
    primitive = asset.primitive
    if primitive is None:
        primitive_str = ""
    elif hasattr(primitive, "value"):
        primitive_str = primitive.value
    else:
        primitive_str = str(primitive)
    return (
        asset.name or "",
        asset.variant or "",
        primitive_str,
    )


def _to_entry(asset: CryptoAsset, group_dim: str = "name") -> HotspotEntry:
    key = asset.name or ""
    if asset.variant:
        key = f"{key}-{asset.variant}"
    return HotspotEntry(
        key=key,
        grouping_dimension=group_dim,
        asset_count=1,
        finding_count=0,
        severity_mix={},
        locations=list(asset.occurrence_locations),
        project_ids=[asset.project_id],
        first_seen=asset.created_at or datetime.now(timezone.utc),
        last_seen=asset.created_at or datetime.now(timezone.utc),
    )


async def compute_scan_delta(
    db: AsyncIOMotorDatabase,
    project_id: str,
    *,
    from_scan: str,
    to_scan: str,
) -> ScanDelta:
    repo = CryptoAssetRepository(db)
    from_assets = await repo.list_by_scan(project_id, from_scan, limit=50_000)
    to_assets = await repo.list_by_scan(project_id, to_scan, limit=50_000)

    from_by_key = {_key(a): a for a in from_assets}
    to_by_key = {_key(a): a for a in to_assets}

    added_keys = to_by_key.keys() - from_by_key.keys()
    removed_keys = from_by_key.keys() - to_by_key.keys()
    unchanged_count = len(to_by_key.keys() & from_by_key.keys())

    added = [_to_entry(to_by_key[k]) for k in added_keys]
    removed = [_to_entry(from_by_key[k]) for k in removed_keys]

    return ScanDelta(
        from_scan_id=from_scan,
        to_scan_id=to_scan,
        added=added,
        removed=removed,
        unchanged_count=unchanged_count,
    )


def _asset_to_envelope_item(asset: CryptoAsset, change: str) -> CryptoDeltaItem:
    primitive = asset.primitive
    if primitive is None:
        prim_str = None
    elif hasattr(primitive, "value"):
        prim_str = primitive.value
    else:
        prim_str = str(primitive)
    return CryptoDeltaItem(
        change=change,
        name=asset.name or "",
        variant=asset.variant,
        primitive=prim_str,
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
    from_assets = await repo.list_by_scan(project_id, from_scan, limit=50_000)
    to_assets = await repo.list_by_scan(project_id, to_scan, limit=50_000)

    from_map = {_key(a): a for a in from_assets}
    to_map = {_key(a): a for a in to_assets}

    added_keys = to_map.keys() - from_map.keys()
    removed_keys = from_map.keys() - to_map.keys()
    unchanged = len(to_map.keys() & from_map.keys())

    items = []
    if change in (None, "all", "added"):
        items.extend(_asset_to_envelope_item(to_map[k], "added") for k in added_keys)
    if change in (None, "all", "removed"):
        items.extend(_asset_to_envelope_item(from_map[k], "removed") for k in removed_keys)

    items.sort(key=lambda i: (i.change, i.name))
    total = len(items)
    total_pages = max(1, (total + page_size - 1) // page_size)
    start = (page - 1) * page_size
    paged = items[start:start + page_size]

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
