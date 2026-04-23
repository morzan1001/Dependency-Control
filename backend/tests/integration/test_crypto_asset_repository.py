"""Tests for CryptoAssetRepository. Uses mocked MongoDB."""

import asyncio
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest

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


class TestListByLimit:
    def test_list_by_scan_respects_limit(self):
        assets_data = [_asset_doc(_id=f"asset-{i}", bom_ref=f"c{i}", name=f"a{i}") for i in range(10)]
        collection = create_mock_collection(find=assets_data[:10])
        db = _make_mock_db(collection)
        repo = CryptoAssetRepository(db)

        listed = asyncio.run(repo.list_by_scan("p2", "s2", limit=10))
        assert len(listed) == 10


class TestListByAssetType:
    def test_list_by_scan_filters_by_asset_type(self):
        algo_data = _asset_doc(_id="a1", bom_ref="a1", name="RSA", asset_type="algorithm")
        collection = create_mock_collection(find=[algo_data])
        db = _make_mock_db(collection)
        repo = CryptoAssetRepository(db)

        algos = asyncio.run(repo.list_by_scan("p3", "s3", limit=100, asset_type=CryptoAssetType.ALGORITHM))
        assert len(algos) == 1
        assert algos[0].name == "RSA"


class TestSummaryCounts:
    def test_summary_counts(self):
        agg_results = [
            {"_id": "algorithm", "count": 2},
            {"_id": "certificate", "count": 1},
        ]
        collection = create_mock_collection(aggregate=agg_results)
        db = _make_mock_db(collection)
        repo = CryptoAssetRepository(db)

        summary = asyncio.run(repo.summary_for_scan("p4", "s4"))
        assert summary["total"] == 3
        assert summary["by_type"]["algorithm"] == 2
        assert summary["by_type"]["certificate"] == 1
