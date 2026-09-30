import pytest

from app.models.crypto_asset import CryptoAsset
from app.repositories.crypto_asset import CryptoAssetRepository
from app.schemas.cbom import CryptoAssetType, CryptoPrimitive
from app.services.analytics._delta_pagination import page_of
from app.services.analytics.crypto_delta import compare_crypto


def _asset(bom_ref, name, primitive=CryptoPrimitive.HASH, scan_id="s1"):
    return CryptoAsset(
        project_id="p1",
        scan_id=scan_id,
        bom_ref=bom_ref,
        name=name,
        asset_type=CryptoAssetType.ALGORITHM,
        primitive=primitive,
    )


@pytest.mark.asyncio
async def test_crypto_envelope_returns_unified_schema(db):
    await CryptoAssetRepository(db).bulk_upsert(
        "p1",
        "s1",
        [
            _asset("a1", "MD5"),
            _asset("a2", "SHA-1"),
        ],
    )
    await CryptoAssetRepository(db).bulk_upsert(
        "p1",
        "s2",
        [
            _asset("b1", "MD5", scan_id="s2"),
            _asset("b2", "SHA-256", scan_id="s2"),
        ],
    )
    resp = await compare_crypto(db, project_id="p1", from_scan="s1", to_scan="s2")
    assert resp.category.value == "crypto"
    assert resp.totals.added == 1
    assert resp.totals.removed == 1
    assert resp.totals.unchanged == 1
    names_added = {i.name for i in resp.items if i.change == "added"}
    assert "SHA-256" in names_added


@pytest.mark.asyncio
async def test_assets_sharing_an_algorithm_are_one_item_counting_all_of_them(db):
    md5_in = [["a.py:1"], ["b.py:2", "a.py:1"], ["c.py:3"]]
    await CryptoAssetRepository(db).bulk_upsert(
        "p1",
        "s1",
        [
            _asset(f"md5-{n}", "MD5").model_copy(update={"occurrence_locations": locations})
            for n, locations in enumerate(md5_in)
        ],
    )
    await CryptoAssetRepository(db).bulk_upsert("p1", "s2", [_asset("b1", "SHA-256", scan_id="s2")])

    resp = page_of(await compare_crypto(db, project_id="p1", from_scan="s1", to_scan="s2"), "removed", 1, 50)

    [item] = resp.items
    assert (item.name, item.asset_count, item.locations) == ("MD5", 3, ["a.py:1", "b.py:2", "c.py:3"])
