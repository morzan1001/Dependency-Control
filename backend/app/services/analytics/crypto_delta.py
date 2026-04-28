"""
Scan-delta computation.

Key tuple: (name, variant, primitive). bom_ref can drift between scans, so
we use the semantic identity of the crypto asset instead.
"""

from datetime import datetime, timezone
from typing import Tuple

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.models.crypto_asset import CryptoAsset
from app.repositories.crypto_asset import CryptoAssetRepository
from app.schemas.analytics import HotspotEntry, ScanDelta


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
