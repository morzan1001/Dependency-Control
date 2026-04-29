"""Unit tests for crypto asset endpoints.

Integration tests via HTTP are complex due to auth setup. These tests verify that:
1. The repository methods work correctly with the endpoints
2. Filtering and pagination logic works
3. Summary aggregation works
"""

import pytest

from app.models.crypto_asset import CryptoAsset
from app.repositories.crypto_asset import CryptoAssetRepository
from app.schemas.cbom import CryptoAssetType, CryptoPrimitive


@pytest.mark.asyncio
async def test_list_crypto_assets_pagination(db):
    """Test that pagination works correctly."""
    await CryptoAssetRepository(db).bulk_upsert(
        "proj",
        "scan",
        [
            CryptoAsset(
                project_id="proj",
                scan_id="scan",
                bom_ref=f"r{i}",
                name=f"algo-{i}",
                asset_type=CryptoAssetType.ALGORITHM,
            )
            for i in range(15)
        ],
    )

    repo = CryptoAssetRepository(db)
    items = await repo.list_by_scan("proj", "scan", limit=10, skip=0)
    total = await repo.count_by_scan("proj", "scan")

    assert total == 15
    assert len(items) == 10


@pytest.mark.asyncio
async def test_list_filters_by_asset_type(db):
    """Test filtering by asset_type."""
    await CryptoAssetRepository(db).bulk_upsert(
        "proj2",
        "sc",
        [
            CryptoAsset(
                project_id="proj2", scan_id="sc", bom_ref="a", name="RSA", asset_type=CryptoAssetType.ALGORITHM
            ),
            CryptoAsset(
                project_id="proj2", scan_id="sc", bom_ref="c", name="cert", asset_type=CryptoAssetType.CERTIFICATE
            ),
        ],
    )

    repo = CryptoAssetRepository(db)
    items = await repo.list_by_scan("proj2", "sc", limit=100, asset_type=CryptoAssetType.CERTIFICATE)

    assert len(items) == 1
    assert items[0].name == "cert"


@pytest.mark.asyncio
async def test_list_filters_by_primitive(db):
    """Test filtering by primitive."""
    await CryptoAssetRepository(db).bulk_upsert(
        "proj3",
        "sc",
        [
            CryptoAsset(
                project_id="proj3",
                scan_id="sc",
                bom_ref="a",
                name="AES",
                asset_type=CryptoAssetType.ALGORITHM,
                primitive=CryptoPrimitive.BLOCK_CIPHER,
            ),
            CryptoAsset(
                project_id="proj3",
                scan_id="sc",
                bom_ref="b",
                name="MD5",
                asset_type=CryptoAssetType.ALGORITHM,
                primitive=CryptoPrimitive.HASH,
            ),
        ],
    )

    repo = CryptoAssetRepository(db)
    items = await repo.list_by_scan("proj3", "sc", limit=100, primitive=CryptoPrimitive.BLOCK_CIPHER)

    assert len(items) == 1
    assert items[0].name == "AES"


@pytest.mark.asyncio
async def test_list_filters_by_name_search(db):
    """Test filtering by name_search (case-insensitive regex)."""
    await CryptoAssetRepository(db).bulk_upsert(
        "proj4",
        "sc",
        [
            CryptoAsset(
                project_id="proj4", scan_id="sc", bom_ref="a", name="AES-256-GCM", asset_type=CryptoAssetType.ALGORITHM
            ),
            CryptoAsset(
                project_id="proj4", scan_id="sc", bom_ref="b", name="RSA-2048", asset_type=CryptoAssetType.ALGORITHM
            ),
        ],
    )

    repo = CryptoAssetRepository(db)
    items = await repo.list_by_scan("proj4", "sc", limit=100, name_search="AES")

    assert len(items) == 1
    assert items[0].name == "AES-256-GCM"


@pytest.mark.asyncio
async def test_get_single_crypto_asset(db):
    """Test get method for a single asset using the composite key that FakeDb uses."""
    asset = CryptoAsset(
        project_id="proj5",
        scan_id="sc",
        bom_ref="x",
        name="AES",
        asset_type=CryptoAssetType.ALGORITHM,
        primitive=CryptoPrimitive.BLOCK_CIPHER,
        key_size_bits=256,
    )
    await CryptoAssetRepository(db).bulk_upsert("proj5", "sc", [asset])

    repo = CryptoAssetRepository(db)
    # In the FakeDb, the _id is a composite key of project:scan:bom_ref
    composite_id = "proj5:sc:x"
    fetched = await repo.get("proj5", composite_id)

    assert fetched is not None
    assert fetched.name == "AES"
    assert fetched.key_size_bits == 256
    assert fetched.primitive == CryptoPrimitive.BLOCK_CIPHER


@pytest.mark.asyncio
async def test_get_nonexistent_asset_returns_none(db):
    """Test get method returns None for nonexistent asset."""
    repo = CryptoAssetRepository(db)
    asset = await repo.get("proj_missing", "nonexistent-id")

    assert asset is None


@pytest.mark.asyncio
async def test_summary_endpoint(db):
    """Test summary method groups by asset_type correctly."""
    await CryptoAssetRepository(db).bulk_upsert(
        "proj6",
        "sc",
        [
            CryptoAsset(
                project_id="proj6", scan_id="sc", bom_ref="a", name="AES", asset_type=CryptoAssetType.ALGORITHM
            ),
            CryptoAsset(
                project_id="proj6", scan_id="sc", bom_ref="b", name="cert1", asset_type=CryptoAssetType.CERTIFICATE
            ),
            CryptoAsset(
                project_id="proj6", scan_id="sc", bom_ref="c", name="cert2", asset_type=CryptoAssetType.CERTIFICATE
            ),
        ],
    )

    repo = CryptoAssetRepository(db)
    summary = await repo.summary_for_scan("proj6", "sc")

    assert summary["total"] == 3
    assert summary["by_type"]["algorithm"] == 1
    assert summary["by_type"]["certificate"] == 2
