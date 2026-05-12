import pytest

from app.repositories.crypto_asset import CryptoAssetRepository
from app.models.crypto_asset import CryptoAsset
from app.schemas.cbom import CryptoAssetType, CryptoPrimitive
from app.services.analytics.crypto_delta import compute_crypto_delta_envelope


def _asset(bom_ref, name, primitive=CryptoPrimitive.HASH, scan_id="s1"):
    return CryptoAsset(
        project_id="p1", scan_id=scan_id, bom_ref=bom_ref,
        name=name, asset_type=CryptoAssetType.ALGORITHM, primitive=primitive,
    )


@pytest.mark.asyncio
async def test_crypto_envelope_returns_unified_schema(db):
    await CryptoAssetRepository(db).bulk_upsert("p1", "s1", [
        _asset("a1", "MD5"), _asset("a2", "SHA-1"),
    ])
    await CryptoAssetRepository(db).bulk_upsert("p1", "s2", [
        _asset("b1", "MD5", scan_id="s2"), _asset("b2", "SHA-256", scan_id="s2"),
    ])
    resp = await compute_crypto_delta_envelope(
        db, project_id="p1", from_scan="s1", to_scan="s2",
        page=1, page_size=50, change=None,
    )
    assert resp.category.value == "crypto"
    assert resp.totals.added == 1
    assert resp.totals.removed == 1
    assert resp.totals.unchanged == 1
    names_added = {i.name for i in resp.items if i.change == "added"}
    assert "SHA-256" in names_added
