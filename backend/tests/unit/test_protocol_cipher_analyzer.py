import pytest

from app.models.crypto_asset import CryptoAsset
from app.models.crypto_policy import CryptoPolicy
from app.models.finding import FindingType, Severity
from app.repositories.crypto_asset import CryptoAssetRepository
from app.repositories.crypto_policy import CryptoPolicyRepository
from app.schemas.cbom import CryptoAssetType
from app.schemas.crypto_policy import CryptoPolicySource, CryptoRule
from app.services.analyzers.crypto.protocol_cipher import ProtocolCipherSuiteAnalyzer


def _protocol(suite_list, bom_ref="p1", project_id="p", scan_id="s"):
    return CryptoAsset(
        project_id=project_id, scan_id=scan_id, bom_ref=bom_ref,
        name="TLS", asset_type=CryptoAssetType.PROTOCOL,
        protocol_type="tls", version="1.2",
        cipher_suites=suite_list,
    )


@pytest.mark.asyncio
async def test_rc4_suite_emits_high_finding(db):
    await CryptoAssetRepository(db).bulk_upsert("p", "s", [
        _protocol(["TLS_RSA_WITH_RC4_128_SHA"]),
    ])
    await CryptoPolicyRepository(db).upsert_system_policy(
        CryptoPolicy(scope="system", version=1, rules=[])
    )
    result = await ProtocolCipherSuiteAnalyzer().analyze(
        sbom={}, project_id="p", scan_id="s", db=db,
    )
    findings = result["findings"]
    rc4 = [f for f in findings if "TLS_RSA_WITH_RC4_128_SHA" in f["details"]["cipher_suite"]]
    assert len(rc4) == 1
    assert rc4[0]["severity"] == "HIGH"
    tags = rc4[0]["details"]["weakness_tags"]
    assert "weak-cipher-rc4" in tags


@pytest.mark.asyncio
async def test_strong_suite_emits_no_finding(db):
    await CryptoAssetRepository(db).bulk_upsert("p2", "s2", [
        _protocol(["TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"]),
    ])
    await CryptoPolicyRepository(db).upsert_system_policy(
        CryptoPolicy(scope="system", version=1, rules=[])
    )
    result = await ProtocolCipherSuiteAnalyzer().analyze(
        sbom={}, project_id="p2", scan_id="s2", db=db,
    )
    assert result["findings"] == []


@pytest.mark.asyncio
async def test_unknown_suite_skipped(db):
    await CryptoAssetRepository(db).bulk_upsert("p3", "s3", [
        _protocol(["TLS_VENDOR_MADE_UP_SUITE"]),
    ])
    await CryptoPolicyRepository(db).upsert_system_policy(
        CryptoPolicy(scope="system", version=1, rules=[])
    )
    result = await ProtocolCipherSuiteAnalyzer().analyze(
        sbom={}, project_id="p3", scan_id="s3", db=db,
    )
    assert result["findings"] == []


@pytest.mark.asyncio
async def test_rule_amplifies_with_weakness_match(db):
    await CryptoAssetRepository(db).bulk_upsert("p4", "s4", [
        _protocol(["TLS_RSA_WITH_AES_128_CBC_SHA"], project_id="p4", scan_id="s4"),
    ])
    rule = CryptoRule(
        rule_id="cnsa20-require-pfs", name="pfs", description="",
        finding_type=FindingType.CRYPTO_WEAK_PROTOCOL,
        default_severity=Severity.MEDIUM,
        source=CryptoPolicySource.CNSA_2_0,
        match_cipher_weaknesses=["no-forward-secrecy"],
    )
    await CryptoPolicyRepository(db).upsert_system_policy(
        CryptoPolicy(scope="system", version=1, rules=[rule])
    )
    result = await ProtocolCipherSuiteAnalyzer().analyze(
        sbom={}, project_id="p4", scan_id="s4", db=db,
    )
    amplified = [f for f in result["findings"] if f["details"].get("rule_id") == "cnsa20-require-pfs"]
    assert len(amplified) == 1
