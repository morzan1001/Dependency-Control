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


def _asset(name, primitive):
    return CryptoAsset(
        project_id="p",
        scan_id="s1",
        bom_ref=f"crypto/algorithm/{name}",
        name=name,
        asset_type=CryptoAssetType.ALGORITHM,
        primitive=primitive,
    )


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
    findings = crypto_findings_for_assets([md5], load_seed_rules(), scanner="crypto_weak_algorithm")

    assert (await _statuses(key, [md5], findings))[_MD5_CONTROLS[key]] == ControlStatus.FAILED


@pytest.mark.asyncio
async def test_a_waived_md5_finding_waives_its_control():
    md5 = _asset("MD5", CryptoPrimitive.HASH)
    findings = crypto_findings_for_assets([md5], load_seed_rules(), scanner="crypto_weak_algorithm")
    for finding in findings:
        finding.update(waived=True, waiver_reason="accepted risk")

    statuses = await _statuses(ReportFramework.NIST_SP_800_131A, [md5], findings)

    assert statuses["NIST-131A-nist-131a-md5"] == ControlStatus.WAIVED


@pytest.mark.asyncio
async def test_a_compliant_inventory_fails_no_control():
    aes = _asset("AES-256", CryptoPrimitive.BLOCK_CIPHER)

    statuses = await _statuses(ReportFramework.NIST_SP_800_131A, [aes], [])

    assert ControlStatus.FAILED not in statuses.values()
    assert ControlStatus.PASSED in statuses.values()
