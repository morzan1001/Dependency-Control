import dataclasses

import pytest

from app.models.crypto_asset import CryptoAsset
from app.models.finding import FindingType, Severity
from app.schemas.cbom import CryptoAssetType, CryptoPrimitive
from app.schemas.compliance import ControlStatus, ReportFramework
from app.services.analyzers.crypto.base import crypto_findings_for_assets
from app.services.cbom_parser import parse_cbom
from app.services.compliance.frameworks import FRAMEWORK_REGISTRY
from app.services.crypto_policy.seeder import load_seed_rules
from tests.helpers.compliance import evaluation_input

_FIPS = FRAMEWORK_REGISTRY[ReportFramework.FIPS_140_3]


def _asset(name, primitive, *, project_id="p", scan_id="s1", **kw):
    return CryptoAsset(
        project_id=project_id,
        scan_id=scan_id,
        bom_ref=f"crypto/algorithm/{name}",
        name=name,
        asset_type=CryptoAssetType.ALGORITHM,
        primitive=primitive,
        **kw,
    )


async def _statuses(assets):
    result = await _FIPS.evaluate(evaluation_input(crypto_assets=assets))
    return {c.control_id: c.status for c in result.controls}


def _weak_algorithm_finding(asset, *, waiver_reason=None):
    """The analyzer's finding for `asset` as persisted, waived when a reason is given."""
    [finding] = [
        f
        for f in crypto_findings_for_assets([asset], load_seed_rules(), scanner="crypto")
        if f["type"] == FindingType.CRYPTO_WEAK_ALGORITHM.value
    ]
    waiver = {"waived": True, "waiver_reason": waiver_reason} if waiver_reason else {}
    return {
        **finding,
        "_id": f"{asset.scan_id}-{finding['id']}",
        "scan_id": asset.scan_id,
        "project_id": asset.project_id,
        **waiver,
    }


async def _hash_control(assets, findings):
    result = await _FIPS.evaluate(evaluation_input(crypto_assets=assets, findings=findings))
    return next(c for c in result.controls if c.control_id == "FIPS-140-3-HASH_FUNCTIONS")


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


@pytest.mark.asyncio
async def test_a_waived_disallowed_algorithm_reads_waived_and_names_the_waiver():
    md5 = _asset("MD5", CryptoPrimitive.HASH)
    finding = _weak_algorithm_finding(md5, waiver_reason="checksum of a public file")

    hashes = await _hash_control([md5], [finding])

    assert hashes.status == ControlStatus.WAIVED
    assert hashes.evidence_finding_ids == [finding["_id"]]
    assert hashes.waiver_reasons == ["checksum of a public file"]


@pytest.mark.asyncio
async def test_a_waiver_in_one_project_leaves_the_same_bom_ref_failing_in_another():
    waived_md5 = _asset("MD5", CryptoPrimitive.HASH, project_id="p1", scan_id="s1")
    open_md5 = _asset("MD5", CryptoPrimitive.HASH, project_id="p2", scan_id="s2")
    findings = [
        _weak_algorithm_finding(waived_md5, waiver_reason="checksum of a public file"),
        _weak_algorithm_finding(open_md5),
    ]

    hashes = await _hash_control([waived_md5, open_md5], findings)

    assert hashes.status == ControlStatus.FAILED


@pytest.mark.asyncio
async def test_a_disallowed_algorithm_nobody_waived_fails_whatever_else_was_waived():
    md5, sha1 = _asset("MD5", CryptoPrimitive.HASH), _asset("SHA-1", CryptoPrimitive.HASH)

    hashes = await _hash_control([md5, sha1], [_weak_algorithm_finding(md5, waiver_reason="accepted")])

    assert hashes.status == ControlStatus.FAILED


@pytest.mark.asyncio
async def test_an_algorithm_whose_cbom_names_no_primitive_is_not_judged():
    """Category controls judge only typed assets, as the seed rules do, so HMAC-SHA1 passes the hash control."""
    cbom = {
        "components": [
            {
                "type": "cryptographic-asset",
                "bom-ref": "crypto/algorithm/md5",
                "name": "MD5",
                "cryptoProperties": {"assetType": "algorithm"},
            }
        ]
    }
    [md5] = [CryptoAsset(project_id="p", scan_id="s1", **a.model_dump()) for a in parse_cbom(cbom).assets]

    assert md5.primitive is None
    assert (await _statuses([md5]))["FIPS-140-3-HASH_FUNCTIONS"] == ControlStatus.NOT_APPLICABLE


def test_a_disallowed_category_control_reads_its_identity_off_the_control():
    control = dataclasses.replace(
        next(c for c in _FIPS.controls if c.control_id == "FIPS-140-3-HASH_FUNCTIONS"),
        control_id="X-1",
        title="t",
        severity=Severity.CRITICAL,
        remediation="r",
    )

    result = control.custom_evaluator(control, evaluation_input())

    assert (result.control_id, result.title, result.severity, result.remediation) == (
        "X-1",
        "t",
        Severity.CRITICAL,
        "r",
    )


@pytest.mark.parametrize("key", [ReportFramework.FIPS_140_3, ReportFramework.ISO_19790])
def test_every_mapped_rule_is_a_seeded_rule(key):
    seeded = {rule.rule_id for rule in load_seed_rules()}

    assert {rule_id for c in FRAMEWORK_REGISTRY[key].controls for rule_id in c.maps_to_rule_ids} <= seeded
