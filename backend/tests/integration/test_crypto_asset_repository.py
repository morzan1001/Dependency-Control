import asyncio
from datetime import datetime, timezone

import pytest

from app.core.init_db import create_indexes
from app.models.crypto_asset import CryptoAsset, CryptoAssetType
from app.repositories.crypto_asset import CryptoAssetRepository
from app.services.cbom_parser import parse_cbom
from tests.helpers.cbom import load_cbom, store_assets
from tests.mocks.mongodb import create_mock_collection, create_mock_db


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
        collection = create_mock_collection(aggregate=assets_data)
        db = create_mock_db({"crypto_assets": collection})
        repo = CryptoAssetRepository(db)

        assets = [
            CryptoAsset(
                project_id="p1", scan_id="s1", bom_ref=f"c{i}", name=f"algo-{i}", asset_type=CryptoAssetType.ALGORITHM
            )
            for i in range(5)
        ]
        asyncio.run(repo.bulk_upsert("p1", "s1", [a.model_dump(by_alias=True) for a in assets], chunk_size=2))
        assert collection.bulk_write.await_count == 3

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
    """The endpoint checks access on project_id only, so a scan_id guessed from another tenant must return nothing."""
    repo = CryptoAssetRepository(db)
    await store_assets(db, "p-own", _SHARED_SCAN, [_asset("p-own", _SHARED_SCAN, "ref-own", "AES-128")])
    await store_assets(db, "p-other", _SHARED_SCAN, [_asset("p-other", _SHARED_SCAN, "ref-other", "AES-256")])

    listed = await repo.list_by_scan("p-own", _SHARED_SCAN, limit=100)

    assert [a.name for a in listed] == ["AES-128"]
    assert await repo.count_by_scan("p-own", _SHARED_SCAN) == 1


@pytest.mark.asyncio
async def test_paging_a_scan_walks_its_assets_name_ascending(db):
    repo = CryptoAssetRepository(db)
    await store_assets(
        db,
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


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_an_asset_is_found_by_the_id_its_listing_names_and_so_is_its_rescan_copy(db):
    await create_indexes(db)
    repo = CryptoAssetRepository(db)
    ingested = _asset("p1", "s1", "ref-a", "AES-128")
    await store_assets(db, "p1", "s1", [ingested])

    (listed,) = await repo.list_by_scan("p1", "s1", limit=10)
    fetched = await repo.get("p1", listed.id)

    assert fetched is not None
    assert fetched.name == "AES-128"
    assert listed.id == ingested.id

    await repo.carry_over_to_scan("p1", "s1", "s2", datetime.now(timezone.utc))
    (carried,) = await repo.list_by_scan("p1", "s2", limit=10)
    fetched_copy = await repo.get("p1", carried.id)

    assert carried.id != listed.id
    assert fetched_copy is not None
    assert fetched_copy.scan_id == "s2"


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_a_read_by_scan_alone_walks_an_index(db):
    """The scan cascade, archive streaming and restore rollback name no project."""
    await create_indexes(db)

    explain = await db.command({"explain": {"find": "crypto_assets", "filter": {"scan_id": {"$in": ["s1"]}}}})

    assert "COLLSCAN" not in str(explain["queryPlanner"]["winningPlan"])


@pytest.mark.asyncio
async def test_storing_parsed_assets_keeps_one_per_ref_and_counts_them_by_type(db):
    written_at = datetime(2026, 10, 1, tzinfo=timezone.utc)
    algorithm, _, protocol = parse_cbom(load_cbom("legacy_crypto_mixed.json"))

    summary = await CryptoAssetRepository(db).store_parsed(
        "p1", "s1", [algorithm, protocol, algorithm], cbom_upload=True, created_at=written_at
    )

    stored = await db.crypto_assets.find({"scan_id": "s1"}).to_list(None)
    assert summary == {"total": 2, "by_type": {"algorithm": 1, "protocol": 1}}
    assert sorted(doc["bom_ref"] for doc in stored) == sorted([algorithm.bom_ref, protocol.bom_ref])
    assert {(doc["cbom_upload"], doc["created_at"]) for doc in stored} == {(True, written_at)}
