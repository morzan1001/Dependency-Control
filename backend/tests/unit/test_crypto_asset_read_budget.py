"""A crypto-asset read returns as much of the scan as its caller budgeted for.

The ingest path accepts MAX_CRYPTO_ASSETS_PER_SCAN assets per upload and the three crypto
analyzers ask for exactly that, so a scan holding more than the repository's own ceiling was
analysed over its first slice only and emitted no finding for the rest, with nothing in the
return value to say so.
"""

import pytest

from app.core.constants import MAX_CRYPTO_ASSETS_PER_SCAN
from app.repositories.crypto_asset import CryptoAssetRepository
from app.schemas.cbom import CryptoAssetType, CryptoPrimitive

_PROJECT = "p1"
_SCAN = "s1"
# Above every ceiling the repository has ever applied to a read, and below the ingest ceiling.
_POPULATION = 10_001


def _seed(db) -> None:
    for index in range(_POPULATION):
        doc = {
            "_id": f"asset-{index:06d}",
            "project_id": _PROJECT,
            "scan_id": _SCAN,
            "bom_ref": f"ref-{index:06d}",
            "name": f"ALG-{index:06d}",
            "asset_type": CryptoAssetType.ALGORITHM.value,
            "primitive": CryptoPrimitive.HASH.value,
        }
        db.crypto_assets._docs[doc["_id"]] = doc


@pytest.mark.asyncio
async def test_a_read_returns_every_asset_its_caller_budgeted_for(db):
    _seed(db)

    listed = await CryptoAssetRepository(db).list_by_scan(_PROJECT, _SCAN, limit=MAX_CRYPTO_ASSETS_PER_SCAN)

    assert len(listed) == _POPULATION


@pytest.mark.asyncio
async def test_a_smaller_budget_is_still_honoured(db):
    _seed(db)

    listed = await CryptoAssetRepository(db).list_by_scan(_PROJECT, _SCAN, limit=1)

    assert len(listed) == 1
