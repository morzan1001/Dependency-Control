from app.models.crypto_asset import CryptoAsset
from app.schemas.cbom import CryptoAssetType, CryptoPrimitive
from app.schemas.compliance import ControlStatus, ReportFramework
from app.services.analytics.scopes import ResolvedScope
from app.services.compliance.frameworks.base import EvaluationInput
from app.services.compliance.frameworks.fips_140_3 import Fips1403Framework


def _asset(name, primitive, **kw):
    return CryptoAsset(
        project_id="p",
        scan_id="s1",
        bom_ref=f"crypto/algorithm/{name}",
        name=name,
        asset_type=CryptoAssetType.ALGORITHM,
        primitive=primitive,
        **kw,
    )


def _eval_input(assets=None):
    return EvaluationInput(
        resolved=ResolvedScope(scope="user", scope_id=None, project_ids=["p"]),
        scope_description="user",
        crypto_assets=assets or [],
        findings=[],
        policy_rules=[],
        policy_version=1,
        iana_catalog_version=1,
        scan_ids=["s1"],
    )


def _statuses(assets):
    result = Fips1403Framework().evaluate(_eval_input(assets))
    return {c.control_id: c.status for c in result.controls}


def test_fips_framework_identity():
    fw = Fips1403Framework()
    assert fw.key == ReportFramework.FIPS_140_3
    assert "FIPS 140-3" in fw.name
    assert fw.disclaimer and "module-level" in fw.disclaimer.lower()


def test_fips_disallowed_algorithm_fails():
    result = Fips1403Framework().evaluate(_eval_input([_asset("MD5", CryptoPrimitive.HASH)]))

    hashes = next(c for c in result.controls if c.control_id == "FIPS-140-3-HASH_FUNCTIONS")
    assert hashes.status == ControlStatus.FAILED
    assert hashes.evidence_asset_bom_refs == ["crypto/algorithm/MD5"]


def test_fips_approved_algorithm_passes():
    statuses = _statuses([_asset("AES-256", CryptoPrimitive.BLOCK_CIPHER, key_size_bits=256)])

    assert statuses["FIPS-140-3-SYMMETRIC_CIPHERS"] == ControlStatus.PASSED


def test_fips_disallowed_category_not_applicable_without_matching_primitive():
    """A hash-only project must report the asymmetric/symmetric disallowed-category controls as NOT_APPLICABLE, not a false PASS."""
    statuses = _statuses([_asset("SHA-256", CryptoPrimitive.HASH)])

    assert statuses["FIPS-140-3-ASYMMETRIC"] == ControlStatus.NOT_APPLICABLE
    assert statuses["FIPS-140-3-SYMMETRIC_CIPHERS"] == ControlStatus.NOT_APPLICABLE
    assert statuses["FIPS-140-3-HASH_FUNCTIONS"] == ControlStatus.PASSED


def test_fips_triple_des_fails_the_symmetric_cipher_control():
    for name in ("3DES", "TripleDES", "TDEA", "3-DES", "DESede"):
        assert _statuses([_asset(name, CryptoPrimitive.BLOCK_CIPHER)])["FIPS-140-3-SYMMETRIC_CIPHERS"] == (
            ControlStatus.FAILED
        ), name


def test_fips_matches_a_disallowed_algorithm_by_variant_and_family_token():
    assert _statuses([_asset("DES-CBC-PKCS5", CryptoPrimitive.BLOCK_CIPHER)])["FIPS-140-3-SYMMETRIC_CIPHERS"] == (
        ControlStatus.FAILED
    )
    assert _statuses([_asset("Digest", CryptoPrimitive.HASH, variant="SHA-1")])["FIPS-140-3-HASH_FUNCTIONS"] == (
        ControlStatus.FAILED
    )


def test_fips_does_not_judge_an_hmac_by_its_digest():
    """HMAC-SHA1 stays approved; the name holds SHA1, but the asset is a MAC, not a hash function."""
    assert _statuses([_asset("HMAC-SHA1", CryptoPrimitive.MAC)])["FIPS-140-3-HASH_FUNCTIONS"] == (
        ControlStatus.NOT_APPLICABLE
    )


def test_fips_key_agreement_and_authenticated_encryption_make_their_categories_applicable():
    statuses = _statuses([_asset("ECDH", CryptoPrimitive.KEY_AGREE), _asset("AES-GCM", CryptoPrimitive.AE)])

    assert statuses["FIPS-140-3-ASYMMETRIC"] == ControlStatus.PASSED
    assert statuses["FIPS-140-3-SYMMETRIC_CIPHERS"] == ControlStatus.PASSED


def test_fips_control_count_reasonable():
    fw = Fips1403Framework()
    # 3 disallowed-category controls (hashes, ciphers, asymmetric) + 1 RSA-min-2048.
    assert len(fw.controls) >= 4
