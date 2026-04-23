import pytest

from app.models.crypto_asset import CryptoAsset
from app.repositories.crypto_asset import CryptoAssetRepository
from app.schemas.cbom import CryptoAssetType, CryptoPrimitive
from app.services.analytics.crypto_delta import compute_scan_delta


def _asset(bom_ref, name, primitive=CryptoPrimitive.HASH, scan_id="s1", variant=None):
    return CryptoAsset(
        project_id="p",
        scan_id=scan_id,
        bom_ref=bom_ref,
        name=name,
        asset_type=CryptoAssetType.ALGORITHM,
        primitive=primitive,
        variant=variant,
    )


@pytest.mark.asyncio
async def test_delta_added_removed_unchanged(db):
    repo = CryptoAssetRepository(db)
    await repo.bulk_upsert(
        "p",
        "s1",
        [
            _asset("a1", "MD5"),
            _asset("a2", "SHA-1"),
        ],
    )
    await repo.bulk_upsert(
        "p",
        "s2",
        [
            _asset("b1", "MD5", scan_id="s2"),
            _asset("b2", "SHA-256", scan_id="s2"),
        ],
    )
    delta = await compute_scan_delta(db, "p", from_scan="s1", to_scan="s2")
    added_names = " ".join(e.key for e in delta.added)
    removed_names = " ".join(e.key for e in delta.removed)
    assert "SHA-256" in added_names
    assert "SHA-1" in removed_names
    assert delta.unchanged_count == 1
