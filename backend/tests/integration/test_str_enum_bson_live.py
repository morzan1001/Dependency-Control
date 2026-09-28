"""A (str, Enum) member reaches the server as its value, in a filter and in a $set alike."""

import pytest

from app.repositories.crypto_asset import _scan_query
from app.schemas.cbom import CryptoAssetType, CryptoPrimitive


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_a_str_enum_filter_and_write_match_the_stored_string_on_real_mongo(db):
    await db.crypto_assets.insert_one(
        {"_id": "a1", "project_id": "p1", "scan_id": "s1", "asset_type": "algorithm", "primitive": "hash"}
    )

    query = _scan_query("p1", "s1", asset_type=CryptoAssetType.ALGORITHM, primitive=CryptoPrimitive.HASH)
    assert [doc["_id"] async for doc in db.crypto_assets.find(query)] == ["a1"]

    await db.crypto_assets.update_one({"_id": "a1"}, {"$set": {"asset_type": CryptoAssetType.CERTIFICATE}})
    stored = await db.crypto_assets.find_one({"_id": "a1"})
    assert type(stored["asset_type"]) is str
    assert stored["asset_type"] == CryptoAssetType.CERTIFICATE.value
