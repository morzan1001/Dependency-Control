"""Crypto-delta: match crypto assets across two scans by ``(name, variant, primitive)``
(``bom_ref`` is regenerated per scan and unusable for matching), as a ScanDeltaResponse.
"""

import asyncio

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.core.constants import MAX_CRYPTO_ASSETS_PER_SCAN
from app.repositories.base import find_window
from app.repositories.crypto_asset import CryptoAssetRepository, scan_query
from app.schemas.scan_delta import (
    CryptoDeltaItem,
    DeltaCategory,
    ScanDeltaResponse,
    ScanDeltaTotals,
)
from app.services.analytics._delta_pagination import by_side, delta_truncation, page_of

# Name-ascending like the asset list, so a capped side is cut at the same alphabetical point on both sides.
_SIDE_SORT: list[tuple[str, int]] = [("name", 1), ("bom_ref", 1)]
_PROJECTION = dict.fromkeys(("name", "variant", "primitive", "occurrence_locations"), 1)


def _key(asset: dict) -> tuple[str, str, str]:
    """Semantic identity used for cross-scan matching."""
    return (asset.get("name") or "", asset.get("variant") or "", asset.get("primitive") or "")


def _group_to_envelope_item(group: list[dict], change: str) -> CryptoDeltaItem:
    return CryptoDeltaItem(
        change=change,
        name=group[0].get("name") or "",
        variant=group[0].get("variant"),
        primitive=group[0].get("primitive"),
        locations=sorted({loc for asset in group for loc in asset.get("occurrence_locations") or []}),
        asset_count=len(group),
    )


async def _side_assets(db: AsyncIOMotorDatabase, project_id: str, scan_id: str) -> tuple[list[dict], int]:
    return await find_window(
        db[CryptoAssetRepository.collection_name],
        scan_query(project_id, scan_id),
        MAX_CRYPTO_ASSETS_PER_SCAN,
        projection=_PROJECTION,
        sort=_SIDE_SORT,
    )


async def compare_crypto(
    db: AsyncIOMotorDatabase, *, project_id: str, from_scan: str, to_scan: str
) -> ScanDeltaResponse:
    """Every crypto change between two scans, sorted, with totals and coverage."""
    (from_assets, from_total), (to_assets, to_total) = await asyncio.gather(
        _side_assets(db, project_id, from_scan), _side_assets(db, project_id, to_scan)
    )

    groups = list(by_side(_key, from_assets, to_assets).values())
    added = [new for gone, new in groups if not gone]
    removed = [gone for gone, new in groups if not new]

    items = [_group_to_envelope_item(group, "added") for group in added]
    items += (_group_to_envelope_item(group, "removed") for group in removed)
    # Sort with variant/primitive tiebreakers so pagination does not depend on fetch order.
    items.sort(key=lambda i: (i.change, i.name, i.variant or "", i.primitive or ""))

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
        items=items,
        truncation=delta_truncation(
            MAX_CRYPTO_ASSETS_PER_SCAN,
            from_compared=len(from_assets),
            from_total=from_total,
            to_compared=len(to_assets),
            to_total=to_total,
        ),
    )


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
    comparison = await compare_crypto(db, project_id=project_id, from_scan=from_scan, to_scan=to_scan)
    return page_of(comparison, change, page, page_size)
