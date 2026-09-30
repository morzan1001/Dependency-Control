import pytest

from app.models.crypto_asset import CryptoAsset
from app.schemas.cbom import CryptoAssetType, CryptoPrimitive
from app.schemas.compliance import ControlStatus, ReportFramework
from app.services.compliance.frameworks import FRAMEWORK_REGISTRY
from tests.helpers.compliance import evaluation_input

_FIPS = FRAMEWORK_REGISTRY[ReportFramework.FIPS_140_3]


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


async def _statuses(assets):
    result = await _FIPS.evaluate(evaluation_input(crypto_assets=assets))
    return {c.control_id: c.status for c in result.controls}


def test_fips_framework_identity():
    assert _FIPS.key == ReportFramework.FIPS_140_3
    assert "FIPS 140-3" in _FIPS.name
    assert _FIPS.disclaimer and "module-level" in _FIPS.disclaimer.lower()


@pytest.mark.asyncio
async def test_fips_disallowed_algorithm_fails():
    result = await _FIPS.evaluate(evaluation_input(crypto_assets=[_asset("MD5", CryptoPrimitive.HASH)]))

    hashes = next(c for c in result.controls if c.control_id == "FIPS-140-3-HASH_FUNCTIONS")
    assert hashes.status == ControlStatus.FAILED
    assert hashes.evidence_asset_bom_refs == ["crypto/algorithm/MD5"]


@pytest.mark.asyncio
async def test_fips_approved_algorithm_passes():
    statuses = await _statuses([_asset("AES-256", CryptoPrimitive.BLOCK_CIPHER, key_size_bits=256)])

    assert statuses["FIPS-140-3-SYMMETRIC_CIPHERS"] == ControlStatus.PASSED


@pytest.mark.asyncio
async def test_fips_disallowed_category_not_applicable_without_matching_primitive():
    """A hash-only project must report the asymmetric/symmetric disallowed-category controls as NOT_APPLICABLE, not a false PASS."""
    statuses = await _statuses([_asset("SHA-256", CryptoPrimitive.HASH)])

    assert statuses["FIPS-140-3-ASYMMETRIC"] == ControlStatus.NOT_APPLICABLE
    assert statuses["FIPS-140-3-SYMMETRIC_CIPHERS"] == ControlStatus.NOT_APPLICABLE
    assert statuses["FIPS-140-3-HASH_FUNCTIONS"] == ControlStatus.PASSED


@pytest.mark.asyncio
async def test_fips_triple_des_fails_the_symmetric_cipher_control():
    for name in ("3DES", "TripleDES", "TDEA", "3-DES", "DESede"):
        assert (await _statuses([_asset(name, CryptoPrimitive.BLOCK_CIPHER)]))["FIPS-140-3-SYMMETRIC_CIPHERS"] == (
            ControlStatus.FAILED
        ), name


@pytest.mark.asyncio
async def test_fips_matches_a_disallowed_algorithm_by_variant_and_family_token():
    assert (await _statuses([_asset("DES-CBC-PKCS5", CryptoPrimitive.BLOCK_CIPHER)]))[
        "FIPS-140-3-SYMMETRIC_CIPHERS"
    ] == (ControlStatus.FAILED)
    assert (await _statuses([_asset("Digest", CryptoPrimitive.HASH, variant="SHA-1")]))[
        "FIPS-140-3-HASH_FUNCTIONS"
    ] == (ControlStatus.FAILED)


@pytest.mark.asyncio
async def test_fips_does_not_judge_an_hmac_by_its_digest():
    """HMAC-SHA1 stays approved; the name holds SHA1, but the asset is a MAC, not a hash function."""
    assert (await _statuses([_asset("HMAC-SHA1", CryptoPrimitive.MAC)]))["FIPS-140-3-HASH_FUNCTIONS"] == (
        ControlStatus.NOT_APPLICABLE
    )


@pytest.mark.asyncio
async def test_fips_key_agreement_and_authenticated_encryption_make_their_categories_applicable():
    statuses = await _statuses([_asset("ECDH", CryptoPrimitive.KEY_AGREE), _asset("AES-GCM", CryptoPrimitive.AE)])

    assert statuses["FIPS-140-3-ASYMMETRIC"] == ControlStatus.PASSED
    assert statuses["FIPS-140-3-SYMMETRIC_CIPHERS"] == ControlStatus.PASSED


def test_fips_control_count_reasonable():
    # 3 disallowed-category controls (hashes, ciphers, asymmetric) + 1 RSA-min-2048.
    assert len(_FIPS.controls) >= 4
