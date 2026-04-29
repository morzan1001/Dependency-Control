from datetime import datetime, timezone

import pytest

from app.models.crypto_asset import CryptoAsset
from app.repositories.crypto_asset import CryptoAssetRepository
from app.schemas.cbom import CryptoAssetType, CryptoPrimitive
from app.services.analytics.crypto_hotspots import CryptoHotspotService
from app.services.analytics.scopes import ResolvedScope


def _asset(bom_ref, name, primitive=None, asset_type=CryptoAssetType.ALGORITHM, project_id="p1", scan_id="s1"):
    return CryptoAsset(
        project_id=project_id,
        scan_id=scan_id,
        bom_ref=bom_ref,
        name=name,
        asset_type=asset_type,
        primitive=primitive,
    )


@pytest.mark.asyncio
async def test_hotspots_group_by_name(db):
    await CryptoAssetRepository(db).bulk_upsert(
        "p1",
        "s1",
        [
            _asset("a1", "MD5", CryptoPrimitive.HASH),
            _asset("a2", "MD5", CryptoPrimitive.HASH),
            _asset("a3", "SHA-256", CryptoPrimitive.HASH),
        ],
    )
    await db.scans.insert_one(
        {
            "_id": "s1",
            "project_id": "p1",
            "status": "completed",
            "created_at": datetime.now(timezone.utc),
        }
    )

    resolved = ResolvedScope(scope="project", scope_id="p1", project_ids=["p1"])
    service = CryptoHotspotService(db)
    result = await service.hotspots(resolved=resolved, group_by="name", limit=10)

    keys = {e.key for e in result.items}
    assert "MD5" in " ".join(keys)
    assert result.scope == "project"
    assert result.grouping_dimension == "name"


@pytest.mark.asyncio
async def test_hotspots_respects_limit(db):
    assets = [_asset(f"a{i}", f"algo-{i}", project_id="p2", scan_id="s2") for i in range(20)]
    await CryptoAssetRepository(db).bulk_upsert("p2", "s2", assets)
    await db.scans.insert_one(
        {
            "_id": "s2",
            "project_id": "p2",
            "status": "completed",
            "created_at": datetime.now(timezone.utc),
        }
    )

    resolved = ResolvedScope(scope="project", scope_id="p2", project_ids=["p2"])
    result = await CryptoHotspotService(db).hotspots(
        resolved=resolved,
        group_by="name",
        limit=5,
    )
    assert len(result.items) <= 5


@pytest.mark.asyncio
async def test_hotspots_group_by_primitive(db):
    await CryptoAssetRepository(db).bulk_upsert(
        "p3",
        "s3",
        [
            _asset("a1", "MD5", CryptoPrimitive.HASH, project_id="p3", scan_id="s3"),
            _asset("a2", "SHA-1", CryptoPrimitive.HASH, project_id="p3", scan_id="s3"),
            _asset("a3", "AES", CryptoPrimitive.BLOCK_CIPHER, project_id="p3", scan_id="s3"),
        ],
    )
    await db.scans.insert_one(
        {
            "_id": "s3",
            "project_id": "p3",
            "status": "completed",
            "created_at": datetime.now(timezone.utc),
        }
    )

    resolved = ResolvedScope(scope="project", scope_id="p3", project_ids=["p3"])
    result = await CryptoHotspotService(db).hotspots(
        resolved=resolved,
        group_by="primitive",
        limit=10,
    )
    keys = {e.key for e in result.items}
    assert "hash" in keys
