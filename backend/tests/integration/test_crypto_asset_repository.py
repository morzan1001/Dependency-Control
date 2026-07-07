"""Tests for CryptoAssetRepository. Uses mocked MongoDB."""

import asyncio
from datetime import datetime, timezone
from unittest.mock import MagicMock


from app.models.crypto_asset import CryptoAsset
from app.repositories.crypto_asset import CryptoAssetRepository
from app.schemas.cbom import CryptoAssetType
from tests.mocks.mongodb import create_mock_collection


def _make_mock_db(collection):
    """Create a mock database that supports dict-style access."""
    db = MagicMock()
    db.__getitem__ = MagicMock(return_value=collection)
    return db


def _asset_doc(**overrides):
    """Create a raw crypto asset document."""
    doc = {
        "_id": "asset-1",
        "project_id": "p1",
        "scan_id": "s1",
        "bom_ref": "c1",
        "name": "SHA-256",
        "asset_type": "algorithm",
        "primitive": "hash",
        "created_at": datetime.now(timezone.utc),
    }
    doc.update(overrides)
    return doc


class TestBulkUpsertAndListByScan:
    def test_bulk_upsert_and_list_by_scan(self):
        assets_data = [_asset_doc(_id=f"asset-{i}", bom_ref=f"c{i}", name=f"algo-{i}") for i in range(5)]
        collection = create_mock_collection(find=assets_data)
        db = _make_mock_db(collection)
        repo = CryptoAssetRepository(db)

        assets = [
            CryptoAsset(
                project_id="p1", scan_id="s1", bom_ref=f"c{i}", name=f"algo-{i}", asset_type=CryptoAssetType.ALGORITHM
            )
            for i in range(5)
        ]
        inserted = asyncio.run(repo.bulk_upsert("p1", "s1", assets, chunk_size=2))
        assert inserted == 5

        listed = asyncio.run(repo.list_by_scan("p1", "s1", limit=100))
        assert len(listed) == 5
