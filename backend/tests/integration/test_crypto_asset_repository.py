"""Tests for CryptoAssetRepository."""

import asyncio
from datetime import datetime, timezone
from unittest.mock import MagicMock

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


def _asset(project_id: str, scan_id: str, bom_ref: str, name: str) -> CryptoAsset:
    return CryptoAsset(
        project_id=project_id,
        scan_id=scan_id,
        bom_ref=bom_ref,
        name=name,
        asset_type=CryptoAssetType.ALGORITHM,
    )


_SHARED_SCAN = "shared-scan-id"


@pytest.mark.asyncio
async def test_a_read_is_confined_to_the_project_that_was_authorised(db):
    """The endpoint checks access on project_id only; scan_id arrives as a caller-supplied query
    parameter, so a scan id guessed from another tenant must return nothing."""
    repo = CryptoAssetRepository(db)
    await repo.bulk_upsert("p-own", _SHARED_SCAN, [_asset("p-own", _SHARED_SCAN, "ref-own", "AES-128")])
    await repo.bulk_upsert("p-other", _SHARED_SCAN, [_asset("p-other", _SHARED_SCAN, "ref-other", "AES-256")])

    listed = await repo.list_by_scan("p-own", _SHARED_SCAN, limit=100)

    assert [a.name for a in listed] == ["AES-128"]
    assert await repo.count_by_scan("p-own", _SHARED_SCAN) == 1


@pytest.mark.asyncio
async def test_paging_a_scan_walks_its_assets_name_ascending(db):
    repo = CryptoAssetRepository(db)
    await repo.bulk_upsert(
        "p1",
        "s1",
        [
            _asset("p1", "s1", "ref-c", "SHA-512"),
            _asset("p1", "s1", "ref-a", "AES-128"),
            _asset("p1", "s1", "ref-b", "RSA-2048"),
        ],
    )

    first = await repo.list_by_scan("p1", "s1", limit=2)
    second = await repo.list_by_scan("p1", "s1", limit=2, skip=2)

    assert [a.name for a in first + second] == ["AES-128", "RSA-2048", "SHA-512"]
