"""Crypto assets survive a rescan.

Only two writers fill `crypto_assets`: /ingest/cbom, under the ingested scan id and with no SBOM in
GridFS, and the engine's embedded-CBOM path. A rescan runs under a fresh scan id and can re-derive
only the second, so without a carry-over every crypto surface reads a rescanned project as having
no cryptography, and the crypto delta reads that as risk having disappeared.
"""

import pytest
from types import SimpleNamespace
from unittest.mock import AsyncMock

from app.models.crypto_asset import CryptoAsset
from app.repositories.crypto_asset import CryptoAssetRepository
from app.schemas.cbom import CryptoAssetType, CryptoPrimitive
from app.services.analysis.engine import _carry_over_crypto_assets

_PROJECT = "p1"
_ORIGINAL_SCAN = "s-original"
_RESCAN = "s-rescan"
_OTHER_SCAN = "s-other"


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
    await repo.bulk_upsert(_PROJECT, scan_id, [_asset(ref, scan_id) for ref in refs])


@pytest.mark.asyncio
async def test_ingested_assets_reach_the_rescan(db):
    repo = CryptoAssetRepository(db)
    await _seed(repo, _ORIGINAL_SCAN, ["ref-a", "ref-b", "ref-c"])

    carried = await repo.carry_over_to_scan(_PROJECT, _ORIGINAL_SCAN, _RESCAN)

    assert carried == 3
    assert await repo.count_by_scan(_PROJECT, _RESCAN) == 3
    assert {a.bom_ref for a in await repo.list_by_scan(_PROJECT, _RESCAN, limit=10)} == {"ref-a", "ref-b", "ref-c"}


@pytest.mark.asyncio
async def test_the_original_scan_keeps_its_assets(db):
    repo = CryptoAssetRepository(db)
    await _seed(repo, _ORIGINAL_SCAN, ["ref-a"])

    await repo.carry_over_to_scan(_PROJECT, _ORIGINAL_SCAN, _RESCAN)

    assert await repo.count_by_scan(_PROJECT, _ORIGINAL_SCAN) == 1


@pytest.mark.asyncio
async def test_carrying_over_twice_does_not_duplicate(db):
    repo = CryptoAssetRepository(db)
    await _seed(repo, _ORIGINAL_SCAN, ["ref-a", "ref-b"])

    await repo.carry_over_to_scan(_PROJECT, _ORIGINAL_SCAN, _RESCAN)
    await repo.carry_over_to_scan(_PROJECT, _ORIGINAL_SCAN, _RESCAN)

    assert await repo.count_by_scan(_PROJECT, _RESCAN) == 2


@pytest.mark.asyncio
async def test_an_embedded_cbom_asset_overwrites_the_carried_copy(db):
    repo = CryptoAssetRepository(db)
    await _seed(repo, _ORIGINAL_SCAN, ["ref-a"])
    await repo.carry_over_to_scan(_PROJECT, _ORIGINAL_SCAN, _RESCAN)

    await repo.bulk_upsert(_PROJECT, _RESCAN, [_asset("ref-a", _RESCAN, name="SHA-256")])

    listed = await repo.list_by_scan(_PROJECT, _RESCAN, limit=10)
    assert [a.name for a in listed] == ["SHA-256"]


@pytest.mark.asyncio
async def test_only_the_named_scan_is_copied(db):
    repo = CryptoAssetRepository(db)
    await _seed(repo, _ORIGINAL_SCAN, ["ref-a"])
    await _seed(repo, _OTHER_SCAN, ["ref-z"])

    await repo.carry_over_to_scan(_PROJECT, _ORIGINAL_SCAN, _RESCAN)

    assert {a.bom_ref for a in await repo.list_by_scan(_PROJECT, _RESCAN, limit=10)} == {"ref-a"}


def _repo_spy(monkeypatch):
    spy = SimpleNamespace(carry_over_to_scan=AsyncMock(return_value=0))
    monkeypatch.setattr("app.repositories.crypto_asset.CryptoAssetRepository", lambda _db: spy)
    return spy


@pytest.mark.asyncio
async def test_engine_carries_over_from_the_original_scan(monkeypatch):
    spy = _repo_spy(monkeypatch)
    scan_doc = SimpleNamespace(is_rescan=True, original_scan_id=_ORIGINAL_SCAN, project_id=_PROJECT)

    await _carry_over_crypto_assets(_RESCAN, scan_doc, SimpleNamespace())

    spy.carry_over_to_scan.assert_awaited_once_with(_PROJECT, _ORIGINAL_SCAN, _RESCAN)


@pytest.mark.asyncio
async def test_engine_carries_nothing_over_for_a_first_scan(monkeypatch):
    spy = _repo_spy(monkeypatch)
    scan_doc = SimpleNamespace(is_rescan=False, original_scan_id=None, project_id=_PROJECT)

    await _carry_over_crypto_assets(_RESCAN, scan_doc, SimpleNamespace())

    spy.carry_over_to_scan.assert_not_awaited()
