import pytest

from app.models.crypto_asset import CryptoAsset
from app.models.crypto_policy import CryptoPolicy
from app.models.finding import FindingType, Severity
from app.repositories.crypto_asset import CryptoAssetRepository
from app.repositories.crypto_policy import CryptoPolicyRepository
from app.schemas.cbom import CryptoAssetType
from app.schemas.crypto_policy import CryptoPolicySource, CryptoRule
from app.services.cbom_parser import parse_cbom
from app.services.crypto_policy.seeder import load_seed_rules
from tests.helpers.analyzers import evaluate_crypto
from tests.helpers.cbom import content_ref


def _protocol(suite_list, bom_ref="p1", project_id="p", scan_id="s"):
    return CryptoAsset(
        project_id=project_id,
        scan_id=scan_id,
        bom_ref=bom_ref,
        name="TLS",
        asset_type=CryptoAssetType.PROTOCOL,
        protocol_type="tls",
        version="1.2",
        cipher_suites=suite_list,
    )


@pytest.mark.asyncio
async def test_rc4_suite_emits_high_finding(db):
    await CryptoAssetRepository(db).bulk_upsert(
        "p",
        "s",
        [
            _protocol(["TLS_RSA_WITH_RC4_128_SHA"]),
        ],
    )
    await CryptoPolicyRepository(db).upsert_system_policy(CryptoPolicy(scope="system", version=1, rules=[]))
    result = await evaluate_crypto("crypto_protocol_cipher", db)
    findings = result["findings"]
    rc4 = [f for f in findings if "TLS_RSA_WITH_RC4_128_SHA" in f["details"]["cipher_suite"]]
    assert len(rc4) == 1
    assert rc4[0]["severity"] == "HIGH"
    tags = rc4[0]["details"]["weakness_tags"]
    assert "weak-cipher-rc4" in tags


@pytest.mark.asyncio
async def test_strong_suite_emits_no_finding(db):
    await CryptoAssetRepository(db).bulk_upsert(
        "p2",
        "s2",
        [
            _protocol(["TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"], project_id="p2", scan_id="s2"),
        ],
    )
    await CryptoPolicyRepository(db).upsert_system_policy(CryptoPolicy(scope="system", version=1, rules=[]))
    result = await evaluate_crypto("crypto_protocol_cipher", db, "p2", "s2")
    assert result["findings"] == []
    assert result["unresolved_cipher_suites"] == 0


@pytest.mark.asyncio
async def test_unknown_suite_skipped(db):
    await CryptoAssetRepository(db).bulk_upsert(
        "p3",
        "s3",
        [
            _protocol(["TLS_VENDOR_MADE_UP_SUITE"], project_id="p3", scan_id="s3"),
        ],
    )
    await CryptoPolicyRepository(db).upsert_system_policy(CryptoPolicy(scope="system", version=1, rules=[]))
    result = await evaluate_crypto("crypto_protocol_cipher", db, "p3", "s3")
    assert result["findings"] == []
    assert result["unresolved_cipher_suites"] == 1


@pytest.mark.asyncio
async def test_rule_amplifies_with_weakness_match(db):
    await CryptoAssetRepository(db).bulk_upsert(
        "p4",
        "s4",
        [
            _protocol(["TLS_RSA_WITH_AES_128_CBC_SHA"], project_id="p4", scan_id="s4"),
        ],
    )
    rule = CryptoRule(
        rule_id="cnsa20-require-pfs",
        name="pfs",
        description="",
        finding_type=FindingType.CRYPTO_WEAK_PROTOCOL,
        default_severity=Severity.MEDIUM,
        source=CryptoPolicySource.CNSA_2_0,
        match_cipher_weaknesses=["no-forward-secrecy"],
    )
    await CryptoPolicyRepository(db).upsert_system_policy(CryptoPolicy(scope="system", version=1, rules=[rule]))
    result = await evaluate_crypto("crypto_protocol_cipher", db, "p4", "s4")
    (finding,) = result["findings"]
    assert finding["severity"] == "MEDIUM"
    assert finding["details"]["rule_id"] == "cnsa20-require-pfs"
    assert [m["rule_id"] for m in finding["details"]["matched_rules"]] == ["cnsa20-require-pfs"]


def _spec_protocol(cipher_suites, evidence=None):
    return {
        "type": "cryptographic-asset",
        "bom-ref": "proto",
        "name": "TLS",
        "cryptoProperties": {
            "assetType": "protocol",
            "protocolProperties": {"type": "tls", "version": "1.2", "cipherSuites": cipher_suites},
        },
        "evidence": evidence or {},
    }


async def _analyze_spec_protocol(db, cipher_suites, pfs_enabled=False, evidence=None, extra_rules=()):
    """A CycloneDX 1.6 protocol asset judged by the seeded policy, with the PFS rule toggled."""
    assets = parse_cbom({"specVersion": "1.6", "components": [_spec_protocol(cipher_suites, evidence)]})
    await CryptoAssetRepository(db).bulk_upsert(
        "p", "s", [CryptoAsset(project_id="p", scan_id="s", **a.model_dump()) for a in assets]
    )
    rules = [
        r.model_copy(update={"enabled": pfs_enabled}) if r.rule_id == "cnsa20-require-pfs" else r
        for r in load_seed_rules()
    ]
    rules.extend(extra_rules)
    await CryptoPolicyRepository(db).upsert_system_policy(CryptoPolicy(scope="system", version=1, rules=rules))
    return await evaluate_crypto("crypto_protocol_cipher", db)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "suite",
    [
        {"name": "SSL_RSA_WITH_RC4_128_MD5"},
        {"name": "tls_rsa_with_rc4_128_md5"},
        {"name": "RC4-MD5", "identifiers": ["0x00", "0x04"]},
        {"name": "RC4-MD5", "identifiers": ["0x0004"]},
    ],
)
async def test_a_weak_suite_is_found_under_its_jsse_lowercase_or_code_point_spelling(db, suite):
    result = await _analyze_spec_protocol(db, [suite])
    (finding,) = result["findings"]
    assert (finding["severity"], finding["details"]["cipher_suite_value"]) == ("HIGH", "0x00,0x04")
    assert finding["details"]["cipher_suite"] == suite["name"]
    assert result["unresolved_cipher_suites"] == 0


@pytest.mark.asyncio
async def test_a_suite_named_only_in_openssl_spelling_is_counted_as_unresolved(db):
    result = await _analyze_spec_protocol(db, [{"name": "RC4-MD5"}, {"name": "TLS_AES_128_GCM_SHA256"}])
    assert result["findings"] == []
    assert result["unresolved_cipher_suites"] == 1


@pytest.mark.asyncio
async def test_a_disabled_rule_leaves_the_catalog_baseline_alone(db):
    result = await _analyze_spec_protocol(db, [{"name": "TLS_RSA_WITH_AES_128_GCM_SHA256"}])
    (finding,) = result["findings"]
    assert finding["severity"] == "LOW"
    assert "rule_id" not in finding["details"]


@pytest.mark.asyncio
async def test_a_weakness_rule_of_another_finding_type_leaves_protocol_findings_alone(db):
    rule = CryptoRule(
        rule_id="algo-no-pfs",
        name="no pfs",
        description="",
        finding_type=FindingType.CRYPTO_WEAK_ALGORITHM,
        default_severity=Severity.CRITICAL,
        source=CryptoPolicySource.CUSTOM,
        match_cipher_weaknesses=["no-forward-secrecy"],
    )
    result = await _analyze_spec_protocol(db, [{"name": "TLS_RSA_WITH_AES_128_GCM_SHA256"}], extra_rules=[rule])
    (finding,) = result["findings"]
    assert finding["severity"] == "LOW"
    assert "rule_id" not in finding["details"]
    assert "matched_rules" not in finding["details"]


@pytest.mark.asyncio
async def test_an_enabled_rule_never_downgrades_a_suite_below_its_baseline(db):
    result = await _analyze_spec_protocol(db, [{"name": "TLS_RSA_WITH_RC4_128_SHA"}], pfs_enabled=True)
    (finding,) = result["findings"]
    assert finding["severity"] == "HIGH"
    assert finding["details"]["rule_id"] == "cnsa20-require-pfs"


@pytest.mark.asyncio
async def test_one_suite_under_two_spellings_is_one_finding_with_a_stable_id(db):
    suites = [{"name": "TLS_RSA_WITH_RC4_128_MD5"}, {"name": "SSL_RSA_WITH_RC4_128_MD5"}]
    first = await _analyze_spec_protocol(db, suites)
    second = await evaluate_crypto("crypto_protocol_cipher", db)
    assert [f["id"] for f in first["findings"]] == [
        f"CRYPTO-crypto_weak_protocol-{content_ref(_spec_protocol(suites))}-TLS_RSA_WITH_RC4_128_MD5"
    ]
    assert [f["id"] for f in second["findings"]] == [f["id"] for f in first["findings"]]


@pytest.mark.asyncio
async def test_a_protocol_finding_carries_the_first_twenty_locations_and_the_total(db):
    result = await _analyze_spec_protocol(
        db,
        [{"name": "TLS_RSA_WITH_RC4_128_SHA"}],
        evidence={"occurrences": [{"location": f"src/Crypto{index}.java", "line": index} for index in range(25)]},
    )
    (finding,) = result["findings"]
    assert finding["found_in"] == [f"src/Crypto{index}.java" for index in range(20)]
    assert finding["details"]["occurrence_count"] == 25


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("suite", "severity"),
    [("TLS_RSA_WITH_IDEA_CBC_SHA", "HIGH"), ("TLS_SHA256_SHA256", "CRITICAL"), ("TLS_SHA384_SHA384", "CRITICAL")],
)
async def test_idea_and_integrity_only_suites_are_rated_like_the_broken_ciphers_they_are(db, suite, severity):
    result = await _analyze_spec_protocol(db, [{"name": suite}])
    (finding,) = result["findings"]
    assert finding["severity"] == severity
