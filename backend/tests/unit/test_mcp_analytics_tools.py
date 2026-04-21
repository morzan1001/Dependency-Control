"""Unit tests for the crypto-analytics MCP tool functions (D.4).

Tests the three new standalone async functions:
  - get_crypto_hotspots
  - get_crypto_trends
  - get_scan_delta
"""

from datetime import datetime, timezone

import pytest

from app.models.crypto_asset import CryptoAsset
from app.repositories.crypto_asset import CryptoAssetRepository
from app.schemas.cbom import CryptoAssetType, CryptoPrimitive


@pytest.mark.asyncio
async def test_mcp_get_crypto_hotspots(db):
    from app.services.chat.tools import get_crypto_hotspots

    await CryptoAssetRepository(db).bulk_upsert("p", "s", [
        CryptoAsset(
            project_id="p",
            scan_id="s",
            bom_ref="a",
            name="MD5",
            asset_type=CryptoAssetType.ALGORITHM,
            primitive=CryptoPrimitive.HASH,
        ),
    ])
    await db.scans.insert_one({
        "_id": "s",
        "project_id": "p",
        "status": "completed",
        "created_at": datetime.now(timezone.utc),
    })

    result = await get_crypto_hotspots(db, project_id="p", group_by="name")

    assert result["total"] >= 1
    assert any(i["key"] and "MD5" in i["key"] for i in result["items"])


@pytest.mark.asyncio
async def test_mcp_get_crypto_trends_empty_range(db):
    from app.services.chat.tools import get_crypto_trends

    result = await get_crypto_trends(
        db,
        project_id="p",
        metric="total_crypto_findings",
        days=30,
    )

    assert result["metric"] == "total_crypto_findings"
    assert result["scope"] == "project"


@pytest.mark.asyncio
async def test_mcp_get_scan_delta(db):
    from app.services.chat.tools import get_scan_delta

    await CryptoAssetRepository(db).bulk_upsert("p", "s1", [
        CryptoAsset(
            project_id="p",
            scan_id="s1",
            bom_ref="a",
            name="MD5",
            asset_type=CryptoAssetType.ALGORITHM,
        ),
    ])
    await CryptoAssetRepository(db).bulk_upsert("p", "s2", [
        CryptoAsset(
            project_id="p",
            scan_id="s2",
            bom_ref="b",
            name="SHA-256",
            asset_type=CryptoAssetType.ALGORITHM,
        ),
    ])

    result = await get_scan_delta(db, project_id="p", from_scan_id="s1", to_scan_id="s2")

    assert result["from_scan_id"] == "s1"
    assert isinstance(result["added"], list)
    assert isinstance(result["removed"], list)
