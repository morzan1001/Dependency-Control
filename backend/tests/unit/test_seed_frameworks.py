"""NIST SP 800-131A, BSI TR-02102 and CNSA 2.0 judge one control per rule of their seed file."""

import pytest

from app.models.crypto_asset import CryptoAsset
from app.schemas.cbom import CryptoAssetType, CryptoPrimitive
from app.schemas.compliance import ControlStatus, ReportFramework
from app.services.analyzers.crypto.base import crypto_findings_for_assets
from app.services.compliance.frameworks import FRAMEWORK_REGISTRY
from app.services.crypto_policy.seeder import load_seed_file, load_seed_rules
from tests.helpers.compliance import evaluation_input

_SEEDS = [
    (ReportFramework.NIST_SP_800_131A, "nist_sp_800_131a.yaml", "NIST-131A"),
    (ReportFramework.BSI_TR_02102, "bsi_tr_02102.yaml", "BSI-02102"),
    (ReportFramework.CNSA_2_0, "cnsa_2_0.yaml", "CNSA20"),
]
_MD5_CONTROLS = {
    ReportFramework.NIST_SP_800_131A: "NIST-131A-nist-131a-md5",
    ReportFramework.BSI_TR_02102: "BSI-02102-bsi-02102-md5",
    ReportFramework.CNSA_2_0: "CNSA20-cnsa20-sha384-min",
}


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


def _persisted(assets):
    """The analyzer's findings for `assets` as the engine stores them, stamped with their scan."""
    return [
        finding | {"_id": finding["id"], "scan_id": "s1"}
        for finding in crypto_findings_for_assets(assets, load_seed_rules(), scanner="crypto_weak_algorithm")
    ]


async def _statuses(key, assets, findings):
    data = evaluation_input(crypto_assets=assets, findings=findings, policy_rules=list(load_seed_rules()))
    return {c.control_id: c.status for c in (await FRAMEWORK_REGISTRY[key].evaluate(data)).controls}


@pytest.mark.parametrize(("key", "seed_file", "prefix"), _SEEDS)
def test_each_seed_rule_becomes_one_control(key, seed_file, prefix):
    framework = FRAMEWORK_REGISTRY[key]

    assert framework.key == key
    assert [(c.control_id, c.maps_to_rule_ids) for c in framework.controls] == [
        (f"{prefix}-{rule.rule_id}", [rule.rule_id]) for rule in load_seed_file(seed_file)
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize("key", list(_MD5_CONTROLS))
async def test_an_md5_finding_fails_the_control_of_every_rule_it_matched(key):
    md5 = _asset("MD5", CryptoPrimitive.HASH)

    assert (await _statuses(key, [md5], _persisted([md5])))[_MD5_CONTROLS[key]] == ControlStatus.FAILED


@pytest.mark.asyncio
async def test_a_waived_md5_finding_waives_its_control():
    md5 = _asset("MD5", CryptoPrimitive.HASH)
    findings = _persisted([md5])
    for finding in findings:
        finding.update(waived=True, waiver_reason="accepted risk")

    statuses = await _statuses(ReportFramework.NIST_SP_800_131A, [md5], findings)

    assert statuses["NIST-131A-nist-131a-md5"] == ControlStatus.WAIVED


@pytest.mark.asyncio
async def test_a_compliant_inventory_fails_no_control():
    aes = _asset("AES-256", CryptoPrimitive.BLOCK_CIPHER, key_size_bits=256)

    statuses = await _statuses(ReportFramework.NIST_SP_800_131A, [aes], [])

    assert ControlStatus.FAILED not in statuses.values()
    assert ControlStatus.PASSED in statuses.values()


async def _nist_md5(assets, findings=()):
    return (await _statuses(ReportFramework.NIST_SP_800_131A, assets, list(findings)))["NIST-131A-nist-131a-md5"]


@pytest.mark.asyncio
async def test_the_md5_control_passes_over_an_inventory_hashing_only_with_sha256():
    assert await _nist_md5([_asset("SHA-256", CryptoPrimitive.HASH)]) == ControlStatus.PASSED


@pytest.mark.asyncio
async def test_the_md5_control_does_not_apply_to_an_inventory_without_hashes():
    aes = _asset("AES-256", CryptoPrimitive.BLOCK_CIPHER, key_size_bits=256)

    assert await _nist_md5([aes]) == ControlStatus.NOT_APPLICABLE


@pytest.mark.asyncio
async def test_an_md5_asset_the_analysis_left_unflagged_withholds_the_md5_control():
    """No finding for an asset the rule matches means the analyzer failed or the policy changed since the scan."""
    md5 = _asset("MD5", CryptoPrimitive.HASH)
    sha256 = _asset("SHA-256", CryptoPrimitive.HASH)

    result = await FRAMEWORK_REGISTRY[ReportFramework.NIST_SP_800_131A].evaluate(
        evaluation_input(crypto_assets=[md5, sha256], findings=[], policy_rules=list(load_seed_rules()))
    )
    control = next(c for c in result.controls if c.control_id == "NIST-131A-nist-131a-md5")

    assert control.status == ControlStatus.NOT_EVALUATED
    assert md5.bom_ref in (control.status_reason or "")


@pytest.mark.asyncio
async def test_a_waived_md5_finding_does_not_cover_a_second_unflagged_md5_asset():
    flagged = _asset("MD5", CryptoPrimitive.HASH)
    unflagged = flagged.model_copy(update={"bom_ref": "crypto/algorithm/MD5-copy"})
    findings = [finding | {"waived": True, "waiver_reason": "accepted risk"} for finding in _persisted([flagged])]

    assert await _nist_md5([flagged, unflagged], findings) == ControlStatus.NOT_EVALUATED


@pytest.mark.asyncio
async def test_the_dh_control_does_not_apply_to_an_inventory_without_dh():
    aes = _asset("AES-256", CryptoPrimitive.BLOCK_CIPHER, key_size_bits=256)

    statuses = await _statuses(ReportFramework.NIST_SP_800_131A, [aes], [])

    assert statuses["NIST-131A-nist-131a-dh-min-2048"] == ControlStatus.NOT_APPLICABLE


@pytest.mark.asyncio
async def test_the_rc4_control_passes_over_a_clean_stream_cipher_inventory():
    chacha = _asset("ChaCha20", CryptoPrimitive.STREAM_CIPHER, key_size_bits=256)

    statuses = await _statuses(ReportFramework.BSI_TR_02102, [chacha], [])

    assert statuses["BSI-02102-bsi-02102-rc4"] == ControlStatus.PASSED


@pytest.mark.asyncio
async def test_the_tls_minimum_control_passes_over_a_tls_13_endpoint():
    tls13 = CryptoAsset(
        project_id="p",
        scan_id="s1",
        bom_ref="crypto/protocol/tls-1.3",
        name="TLS",
        asset_type=CryptoAssetType.PROTOCOL,
        protocol_type="tls",
        version="1.3",
    )

    statuses = await _statuses(ReportFramework.BSI_TR_02102, [tls13], [])

    assert statuses["BSI-02102-bsi-02102-tls-min-12"] == ControlStatus.PASSED
