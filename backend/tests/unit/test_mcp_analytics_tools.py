"""Unit tests for the crypto-analytics MCP tool functions."""

from datetime import datetime, time, timedelta, timezone

import pytest

from app.models.crypto_asset import CryptoAsset
from app.models.user import User
from app.repositories.crypto_asset import CryptoAssetRepository
from app.schemas.cbom import CryptoAssetType, CryptoPrimitive
from app.services.chat.tools import ChatToolRegistry
from tests.helpers.permission_presets import PRESET_ADMIN


def _admin() -> User:
    return User(id="admin-1", username="admin", email="admin@test.com", permissions=list(PRESET_ADMIN))


async def _seed_md5_scan(db):
    await CryptoAssetRepository(db).bulk_upsert(
        "p",
        "s",
        [
            CryptoAsset(
                project_id="p",
                scan_id="s",
                bom_ref="a",
                name="MD5",
                asset_type=CryptoAssetType.ALGORITHM,
                primitive=CryptoPrimitive.HASH,
            ),
        ],
    )
    await db.projects.insert_one({"_id": "p", "name": "p", "latest_scan_id": "s"})
    await db.scans.insert_one(
        {
            "_id": "s",
            "project_id": "p",
            "status": "completed",
            "created_at": datetime.now(timezone.utc),
        }
    )


@pytest.mark.asyncio
async def test_mcp_get_crypto_hotspots(db):
    from app.services.chat.tools import get_crypto_hotspots

    await _seed_md5_scan(db)

    result = await get_crypto_hotspots(db, project_id="p", group_by="name", limit=20)

    assert result["total"] >= 1
    assert any(i["key"] and "MD5" in i["key"] for i in result["items"])


@pytest.mark.asyncio
async def test_a_null_grouping_groups_hotspots_by_name(db):
    await _seed_md5_scan(db)

    result = await ChatToolRegistry().execute_tool(
        "get_crypto_hotspots", {"project_id": "p", "group_by": None}, _admin(), db
    )

    assert result["grouping_dimension"] == "name"


@pytest.mark.asyncio
async def test_a_null_metric_trends_the_total_crypto_findings(db):
    await _seed_md5_scan(db)

    result = await ChatToolRegistry().execute_tool(
        "get_crypto_trends", {"project_id": "p", "metric": None}, _admin(), db
    )

    assert result["metric"] == "total_crypto_findings"


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
async def test_a_repeated_trend_question_is_answered_from_the_cache_for_the_rest_of_the_day(db):
    from app.services.chat.tools import get_crypto_trends

    first = await get_crypto_trends(db, project_id="p", metric="total_crypto_findings", days=30)
    again = await get_crypto_trends(db, project_id="p", metric="total_crypto_findings", days=30)

    assert again["cache_hit"] is True
    assert first["range_end"] > datetime.now(timezone.utc)
    assert first["range_end"].timetz() == time(0, tzinfo=timezone.utc)
    assert first["range_end"] - first["range_start"] == timedelta(days=30)
