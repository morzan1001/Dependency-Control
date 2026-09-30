from app.models.crypto_asset import CryptoAsset
from app.schemas.cbom import CryptoAssetType, CryptoPrimitive
from app.schemas.compliance import ControlStatus, ReportFramework
from app.services.analytics.scopes import ResolvedScope
from app.services.compliance.frameworks.base import EvaluationInput
from app.services.compliance.frameworks.iso_19790 import Iso19790Framework


def _input(assets=None):
    return EvaluationInput(
        resolved=ResolvedScope(scope="user", scope_id=None, project_ids=["p"]),
        scope_description="u",
        crypto_assets=assets or [],
        findings=[],
        policy_rules=[],
        policy_version=1,
        iana_catalog_version=1,
        scan_ids=["s1"],
    )


def test_iso_identity_and_disclaimer():
    fw = Iso19790Framework()
    assert fw.key == ReportFramework.ISO_19790
    assert "ISO/IEC 19790" in fw.name
    assert fw.disclaimer
    assert "Annex D" in fw.disclaimer


def test_iso_control_ids_rewritten():
    fw = Iso19790Framework()
    for c in fw.controls:
        assert c.control_id.startswith("ISO-19790-")
    assert len(fw.controls) >= 4


def test_iso_evaluation_matches_fips_behaviour():
    md5 = CryptoAsset(
        project_id="p",
        scan_id="s1",
        bom_ref="crypto/algorithm/md5",
        name="MD5",
        asset_type=CryptoAssetType.ALGORITHM,
        primitive=CryptoPrimitive.HASH,
    )

    result = Iso19790Framework().evaluate(_input(assets=[md5]))

    hashes = next(c for c in result.controls if c.control_id == "ISO-19790-HASH_FUNCTIONS")
    assert hashes.status == ControlStatus.FAILED
