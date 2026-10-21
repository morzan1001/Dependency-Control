"""A rescan can re-derive only embedded-CBOM assets, so /ingest/cbom assets must be carried over."""

from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
import pytest_asyncio

from app.core.init_db import create_indexes
from app.models.crypto_asset import CryptoAsset
from app.repositories.crypto_asset import CryptoAssetRepository
from app.models.crypto_asset import CryptoAssetType, CryptoPrimitive
from app.services.analysis.engine import _carry_over_crypto_assets
from tests.helpers.cbom import store_assets
from tests.mocks.fake_mongo import FakeDatabase

_PROJECT = "p1"
_ORIGINAL_SCAN = "s-original"
_RESCAN = "s-rescan"
_OTHER_SCAN = "s-other"
_RESCANNED_AT = datetime(2026, 10, 1, tzinfo=timezone.utc)


@pytest_asyncio.fixture
async def db():
    database = FakeDatabase()
    await create_indexes(database)
    return database


def _asset(bom_ref: str, scan_id: str, name: str = "MD5") -> CryptoAsset:
    return CryptoAsset(
        project_id=_PROJECT,
        scan_id=scan_id,
        bom_ref=bom_ref,
        name=name,
        asset_type=CryptoAssetType.ALGORITHM,
        primitive=CryptoPrimitive.HASH,
    )


async def _seed(repo: CryptoAssetRepository, scan_id: str, refs: list[str]) -> None:
    await store_assets(repo.db, _PROJECT, scan_id, [_asset(ref, scan_id) for ref in refs])


@pytest.mark.asyncio
async def test_ingested_assets_reach_the_rescan(db):
    repo = CryptoAssetRepository(db)
    await _seed(repo, _ORIGINAL_SCAN, ["ref-a", "ref-b", "ref-c"])

    await repo.carry_over_to_scan(_PROJECT, _ORIGINAL_SCAN, _RESCAN, _RESCANNED_AT)

    assert await repo.count_by_scan(_PROJECT, _RESCAN) == 3
    assert {a.bom_ref for a in await repo.list_by_scan(_PROJECT, _RESCAN, limit=10)} == {"ref-a", "ref-b", "ref-c"}


@pytest.mark.asyncio
async def test_the_original_scan_keeps_its_assets(db):
    repo = CryptoAssetRepository(db)
    await _seed(repo, _ORIGINAL_SCAN, ["ref-a"])

    await repo.carry_over_to_scan(_PROJECT, _ORIGINAL_SCAN, _RESCAN, _RESCANNED_AT)

    assert await repo.count_by_scan(_PROJECT, _ORIGINAL_SCAN) == 1


@pytest.mark.asyncio
async def test_carrying_over_twice_does_not_duplicate(db):
    repo = CryptoAssetRepository(db)
    await _seed(repo, _ORIGINAL_SCAN, ["ref-a", "ref-b"])

    await repo.carry_over_to_scan(_PROJECT, _ORIGINAL_SCAN, _RESCAN, _RESCANNED_AT)
    await repo.carry_over_to_scan(_PROJECT, _ORIGINAL_SCAN, _RESCAN, _RESCANNED_AT)

    assert await repo.count_by_scan(_PROJECT, _RESCAN) == 2


@pytest.mark.asyncio
async def test_an_embedded_cbom_asset_overwrites_the_carried_copy(db):
    repo = CryptoAssetRepository(db)
    await _seed(repo, _ORIGINAL_SCAN, ["ref-a"])
    await repo.carry_over_to_scan(_PROJECT, _ORIGINAL_SCAN, _RESCAN, _RESCANNED_AT)

    await store_assets(db, _PROJECT, _RESCAN, [_asset("ref-a", _RESCAN, name="SHA-256")])

    listed = await repo.list_by_scan(_PROJECT, _RESCAN, limit=10)
    assert [a.name for a in listed] == ["SHA-256"]


@pytest.mark.asyncio
async def test_a_carry_over_keeps_the_assets_the_rescan_already_holds(db):
    repo = CryptoAssetRepository(db)
    source_b = _asset("ref-b", _ORIGINAL_SCAN)
    held = _asset("ref-a", _RESCAN, name="SHA-256")
    await store_assets(db, _PROJECT, _ORIGINAL_SCAN, [_asset("ref-a", _ORIGINAL_SCAN), source_b])
    await store_assets(db, _PROJECT, _RESCAN, [held])

    await repo.carry_over_to_scan(_PROJECT, _ORIGINAL_SCAN, _RESCAN, _RESCANNED_AT)

    listed = await repo.list_by_scan(_PROJECT, _RESCAN, limit=10)
    assert {(a.bom_ref, a.id, a.name) for a in listed} == {
        ("ref-a", held.id, "SHA-256"),
        ("ref-b", f"{_RESCAN}:{source_b.id}", "MD5"),
    }


@pytest.mark.asyncio
async def test_only_the_named_scan_is_copied(db):
    repo = CryptoAssetRepository(db)
    await _seed(repo, _ORIGINAL_SCAN, ["ref-a"])
    await _seed(repo, _OTHER_SCAN, ["ref-z"])

    await repo.carry_over_to_scan(_PROJECT, _ORIGINAL_SCAN, _RESCAN, _RESCANNED_AT)

    assert {a.bom_ref for a in await repo.list_by_scan(_PROJECT, _RESCAN, limit=10)} == {"ref-a"}


@pytest.mark.asyncio
async def test_a_carried_asset_is_dated_by_the_rescan_and_a_held_one_keeps_its_date(db):
    repo = CryptoAssetRepository(db)
    ingested_at = datetime(2026, 9, 1, tzinfo=timezone.utc)
    held_at = datetime(2026, 10, 2, tzinfo=timezone.utc)
    await store_assets(
        db,
        _PROJECT,
        _ORIGINAL_SCAN,
        [_asset(ref, _ORIGINAL_SCAN).model_copy(update={"created_at": ingested_at}) for ref in ("ref-a", "ref-b")],
    )
    await store_assets(db, _PROJECT, _RESCAN, [_asset("ref-a", _RESCAN).model_copy(update={"created_at": held_at})])

    await repo.carry_over_to_scan(_PROJECT, _ORIGINAL_SCAN, _RESCAN, _RESCANNED_AT)

    dated = {a.bom_ref: a.created_at for a in await repo.list_by_scan(_PROJECT, _RESCAN, limit=10)}
    assert dated == {"ref-a": held_at, "ref-b": _RESCANNED_AT}
    assert {a.created_at for a in await repo.list_by_scan(_PROJECT, _ORIGINAL_SCAN, limit=10)} == {ingested_at}


def _repo_spy(monkeypatch):
    spy = SimpleNamespace(carry_over_to_scan=AsyncMock())
    monkeypatch.setattr("app.services.analysis.engine.CryptoAssetRepository", lambda _db: spy)
    return spy


@pytest.mark.asyncio
async def test_engine_carries_over_from_the_original_scan(monkeypatch):
    spy = _repo_spy(monkeypatch)
    scan_doc = SimpleNamespace(
        is_rescan=True, original_scan_id=_ORIGINAL_SCAN, project_id=_PROJECT, created_at=_RESCANNED_AT
    )

    await _carry_over_crypto_assets(_RESCAN, scan_doc, SimpleNamespace())

    spy.carry_over_to_scan.assert_awaited_once_with(_PROJECT, _ORIGINAL_SCAN, _RESCAN, _RESCANNED_AT)


@pytest.mark.asyncio
async def test_engine_carries_nothing_over_for_a_first_scan(monkeypatch):
    spy = _repo_spy(monkeypatch)
    scan_doc = SimpleNamespace(is_rescan=False, original_scan_id=None, project_id=_PROJECT)

    await _carry_over_crypto_assets(_RESCAN, scan_doc, SimpleNamespace())

    spy.carry_over_to_scan.assert_not_awaited()
