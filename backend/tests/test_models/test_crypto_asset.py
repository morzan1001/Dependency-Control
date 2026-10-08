from datetime import datetime

from app.models.crypto_asset import CryptoAsset
from app.schemas.cbom import CryptoAssetType


def test_crypto_asset_minimal():
    a = CryptoAsset(
        project_id="p1",
        scan_id="s1",
        bom_ref="c1",
        name="SHA-1",
        asset_type=CryptoAssetType.ALGORITHM,
    )
    assert a.project_id == "p1"
    assert a.id
    assert isinstance(a.created_at, datetime)
