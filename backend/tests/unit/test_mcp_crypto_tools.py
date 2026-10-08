"""Unit tests for the crypto-asset chat tools in app.services.chat.tools."""

from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest
import pytest_asyncio

from app.core.constants import SCAN_STATUS_COMPLETED
from app.models.crypto_asset import CryptoAsset
from app.repositories.crypto_asset import CryptoAssetRepository
from app.schemas.cbom import CryptoAssetType, CryptoPrimitive
from app.services.chat.tools import ChatToolRegistry
from tests.helpers.auth import make_admin
from tests.mocks.mongodb import create_mock_collection

_PROJECT = "p-crypto"
_SCAN = "s-crypto"
_BRANCH = "main"


def _make_mock_db(collection):
    db = MagicMock()
    db.__getitem__ = MagicMock(return_value=collection)
    return db


def _algorithm(bom_ref: str, name: str, primitive: CryptoPrimitive) -> CryptoAsset:
    return CryptoAsset(
        project_id=_PROJECT,
        scan_id=_SCAN,
        bom_ref=bom_ref,
        name=name,
        asset_type=CryptoAssetType.ALGORITHM,
        primitive=primitive,
    )


@pytest_asyncio.fixture
async def with_assets(db):
    db.projects._docs[_PROJECT] = {
        "_id": _PROJECT,
        "name": "P",
        "default_branch": _BRANCH,
        "deleted_branches": [],
        "latest_scan_id": _SCAN,
    }
    db.scans._docs[_SCAN] = {
        "_id": _SCAN,
        "project_id": _PROJECT,
        "branch": _BRANCH,
        "status": SCAN_STATUS_COMPLETED,
        "created_at": datetime(2026, 9, 1, tzinfo=timezone.utc),
    }
    await CryptoAssetRepository(db).bulk_upsert(
        _PROJECT,
        _SCAN,
        [
            _algorithm("ref-md5", "MD5", CryptoPrimitive.HASH),
            _algorithm("ref-sha1", "SHA-1", CryptoPrimitive.HASH),
            _algorithm("ref-aes", "AES-128", CryptoPrimitive.BLOCK_CIPHER),
        ],
    )
    return db


@pytest.mark.asyncio
async def test_the_asset_total_counts_the_filtered_population(with_assets):
    result = await ChatToolRegistry().execute_tool(
        "list_crypto_assets", {"project_id": _PROJECT, "primitive": "hash", "limit": 1}, make_admin(), with_assets
    )

    assert [i["name"] for i in result["items"]] == ["MD5"]
    assert result["items_total"] == 2


@pytest.mark.asyncio
@pytest.mark.parametrize(("argument", "value"), [("primitive", "hashes"), ("asset_type", "certificates")])
async def test_an_unknown_asset_filter_is_refused_rather_than_dropped(with_assets, argument, value):
    result = await ChatToolRegistry().execute_tool(
        "list_crypto_assets", {"project_id": _PROJECT, argument: value}, make_admin(), with_assets
    )

    assert "items" not in result
    assert argument in result["error"]


@pytest.mark.asyncio
async def test_an_unknown_report_framework_is_refused_rather_than_dropped(db):
    result = await ChatToolRegistry().execute_tool("list_compliance_reports", {"framework": "nist"}, make_admin(), db)

    assert "reports" not in result
    assert "framework" in result["error"]


@pytest.mark.asyncio
async def test_mcp_get_crypto_summary():
    from app.services.chat.tools import get_crypto_summary

    agg_results = [{"_id": "algorithm", "count": 1}]
    mock_col = create_mock_collection(aggregate=agg_results, count_documents=1)
    db = _make_mock_db(mock_col)

    result = await get_crypto_summary(db, project_id="p2", scan_id="s2")
    assert result["total"] == 1
    assert "by_type" in result
