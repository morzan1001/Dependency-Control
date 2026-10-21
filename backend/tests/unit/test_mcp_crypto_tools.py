from datetime import datetime, timezone

import pytest
import pytest_asyncio

from app.core.constants import SCAN_STATUS_COMPLETED
from app.models.crypto_asset import CryptoAsset
from app.models.crypto_asset import CryptoAssetType, CryptoPrimitive
from app.services.chat.tools import ChatToolRegistry
from tests.helpers.auth import make_admin
from tests.helpers.cbom import store_assets

_PROJECT = "p-crypto"
_SCAN = "s-crypto"
_BRANCH = "main"


def _algorithm(bom_ref: str, name: str, primitive: CryptoPrimitive) -> CryptoAsset:
    return CryptoAsset(
        project_id=_PROJECT,
        scan_id=_SCAN,
        bom_ref=bom_ref,
        name=name,
        asset_type=CryptoAssetType.ALGORITHM,
        primitive=primitive,
    )


def _seed_head_scan(db, scan_type: str | None = None) -> None:
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
        "scan_type": scan_type,
        "created_at": datetime(2026, 9, 1, tzinfo=timezone.utc),
    }


@pytest_asyncio.fixture
async def with_assets(db):
    _seed_head_scan(db)
    await store_assets(
        db,
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
@pytest.mark.parametrize("tool", ["get_crypto_summary", "list_crypto_assets"])
@pytest.mark.parametrize(
    ("scan_type", "assets", "evaluated"),
    [(None, [], False), ("cbom", [], True), (None, ["AES-128"], True)],
    ids=["no-cbom", "empty-cbom", "assets"],
)
async def test_the_crypto_tools_tell_an_empty_cbom_from_a_missing_one(db, tool, scan_type, assets, evaluated):
    _seed_head_scan(db, scan_type)
    await store_assets(
        db, _PROJECT, _SCAN, [_algorithm(f"ref-{name}", name, CryptoPrimitive.BLOCK_CIPHER) for name in assets]
    )

    result = await ChatToolRegistry().execute_tool(tool, {"project_id": _PROJECT, "limit": 10}, make_admin(), db)

    assert result["cbom_evaluated"] is evaluated
    if tool == "get_crypto_summary":
        assert result["total"] == len(assets)
        assert result["by_type"] == ({"algorithm": len(assets)} if assets else {})
