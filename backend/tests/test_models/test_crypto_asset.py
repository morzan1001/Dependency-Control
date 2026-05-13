from datetime import datetime, timezone

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
    assert a.id  # default uuid
    assert isinstance(a.created_at, datetime)


def test_crypto_asset_populate_by_name_alias():
    # _id alias should work (round-trip from mongo-style dict)
    data = {
        "_id": "deadbeef",
        "project_id": "p1",
        "scan_id": "s1",
        "bom_ref": "c1",
        "name": "SHA-256",
        "asset_type": "algorithm",
        "primitive": "hash",
        "created_at": datetime.now(timezone.utc),
    }
    a = CryptoAsset.model_validate(data)
    assert a.id == "deadbeef"
    dumped = a.model_dump(by_alias=True)
    assert dumped["_id"] == "deadbeef"


