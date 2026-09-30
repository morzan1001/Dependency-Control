import pytest

from app.models.crypto_asset import CryptoAsset
from app.schemas.cbom import CryptoAssetType, CryptoPrimitive
from app.schemas.compliance import ControlStatus, ReportFramework
from app.services.compliance.frameworks import FRAMEWORK_REGISTRY
from tests.helpers.compliance import evaluation_input

_ISO = FRAMEWORK_REGISTRY[ReportFramework.ISO_19790]


def test_iso_identity_and_disclaimer():
    assert _ISO.key == ReportFramework.ISO_19790
    assert "ISO/IEC 19790" in _ISO.name
    assert _ISO.disclaimer
    assert "Annex D" in _ISO.disclaimer


def test_iso_control_ids_rewritten():
    for c in _ISO.controls:
        assert c.control_id.startswith("ISO-19790-")
    assert len(_ISO.controls) >= 4


@pytest.mark.asyncio
async def test_iso_evaluation_matches_fips_behaviour():
    md5 = CryptoAsset(
        project_id="p",
        scan_id="s1",
        bom_ref="crypto/algorithm/md5",
        name="MD5",
        asset_type=CryptoAssetType.ALGORITHM,
        primitive=CryptoPrimitive.HASH,
    )

    result = await _ISO.evaluate(evaluation_input(crypto_assets=[md5]))

    hashes = next(c for c in result.controls if c.control_id == "ISO-19790-HASH_FUNCTIONS")
    assert hashes.status == ControlStatus.FAILED
