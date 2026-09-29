import pytest

from app.models.crypto_asset import CryptoAsset
from app.models.finding import FindingType, Severity
from app.schemas.cbom import CryptoAssetType, CryptoPrimitive
from app.schemas.crypto_policy import CryptoPolicySource, CryptoRule
from app.services.analyzers.crypto.matcher import asset_in_rule_scope, rule_matches
from app.services.cbom_parser import parse_crypto_components
from app.services.crypto_policy.seeder import load_seed_rules


def _asset(**kw):
    defaults = {
        "project_id": "p",
        "scan_id": "s",
        "bom_ref": "r",
        "name": "X",
        "asset_type": CryptoAssetType.ALGORITHM,
    }
    defaults.update(kw)
    return CryptoAsset(**defaults)


def _rule(**kw):
    defaults = {
        "rule_id": "r",
        "name": "n",
        "description": "",
        "finding_type": FindingType.CRYPTO_WEAK_ALGORITHM,
        "default_severity": Severity.HIGH,
        "source": CryptoPolicySource.NIST_SP_800_131A,
    }
    defaults.update(kw)
    return CryptoRule(**defaults)


@pytest.mark.parametrize(
    "name,patterns,expected",
    [
        ("MD5", ["MD5"], True),
        ("md5", ["MD5"], True),
        ("MD-5", ["MD*"], True),
        ("SHA-256", ["MD5", "SHA-1"], False),
    ],
)
def test_name_pattern_matching(name, patterns, expected):
    asset = _asset(name=name)
    rule = _rule(match_name_patterns=patterns)
    assert rule_matches(asset, rule) is expected


@pytest.mark.parametrize(
    "asset_name,variant,patterns,expected",
    [
        ("generic", "RSA-2048", ["RSA*"], True),
        ("generic", None, ["RSA*"], False),
    ],
)
def test_variant_matching(asset_name, variant, patterns, expected):
    asset = _asset(name=asset_name, variant=variant)
    rule = _rule(match_name_patterns=patterns)
    assert rule_matches(asset, rule) is expected


def test_primitive_match_required():
    asset = _asset(name="SHA-1", primitive=CryptoPrimitive.HASH)
    rule_hash = _rule(match_name_patterns=["SHA-1"], match_primitive=CryptoPrimitive.HASH)
    rule_block = _rule(match_name_patterns=["SHA-1"], match_primitive=CryptoPrimitive.BLOCK_CIPHER)
    assert rule_matches(asset, rule_hash) is True
    assert rule_matches(asset, rule_block) is False


class TestAssetInRuleScope:
    """asset_in_rule_scope ignores threshold criteria so a compliant asset still counts as within the rule's subject scope."""

    def test_compliant_rsa_key_is_in_scope_but_not_a_violation(self):
        rule = _rule(match_name_patterns=["RSA"], match_primitive=CryptoPrimitive.PKE, match_min_key_size_bits=2048)
        compliant = _asset(name="RSA", primitive=CryptoPrimitive.PKE, key_size_bits=4096)
        # rule_matches = violation predicate -> compliant key is NOT a violation
        assert rule_matches(compliant, rule) is False
        # scope predicate -> the RSA subject IS present, so the control applies
        assert asset_in_rule_scope(compliant, rule) is True

    def test_weak_rsa_key_is_in_scope(self):
        rule = _rule(match_name_patterns=["RSA"], match_primitive=CryptoPrimitive.PKE, match_min_key_size_bits=2048)
        weak = _asset(name="RSA", primitive=CryptoPrimitive.PKE, key_size_bits=1024)
        assert asset_in_rule_scope(weak, rule) is True

    def test_unrelated_primitive_not_in_scope(self):
        rule = _rule(match_name_patterns=["RSA"], match_primitive=CryptoPrimitive.PKE, match_min_key_size_bits=2048)
        aes = _asset(name="AES", primitive=CryptoPrimitive.BLOCK_CIPHER, key_size_bits=256)
        assert asset_in_rule_scope(aes, rule) is False

    def test_name_mismatch_not_in_scope(self):
        rule = _rule(match_name_patterns=["RSA"], match_primitive=CryptoPrimitive.PKE)
        dsa = _asset(name="DSA", primitive=CryptoPrimitive.PKE)
        assert asset_in_rule_scope(dsa, rule) is False


@pytest.mark.parametrize(
    "key_size,threshold,expected",
    [
        (1024, 2048, True),
        (2048, 2048, False),
        (4096, 2048, False),
        (None, 2048, False),
    ],
)
def test_min_key_size_matching(key_size, threshold, expected):
    asset = _asset(name="RSA", key_size_bits=key_size)
    rule = _rule(match_name_patterns=["RSA"], match_min_key_size_bits=threshold)
    assert rule_matches(asset, rule) is expected


@pytest.mark.parametrize(
    "proto,version,match_list,expected",
    [
        ("tls", "1.0", ["tls 1.0", "tls 1.1"], True),
        ("tls", "1.2", ["tls 1.0", "tls 1.1"], False),
        ("TLS", "1.0", ["tls 1.0"], True),
    ],
)
def test_protocol_version_matching(proto, version, match_list, expected):
    asset = _asset(
        asset_type=CryptoAssetType.PROTOCOL,
        protocol_type=proto,
        version=version,
    )
    rule = _rule(match_protocol_versions=match_list)
    assert rule_matches(asset, rule) is expected


@pytest.mark.parametrize(
    "name,primitive,expected",
    [
        ("RSA", CryptoPrimitive.PKE, True),
        ("ECDSA", CryptoPrimitive.SIGNATURE, True),
        ("DH", CryptoPrimitive.KEY_AGREE, True),
        ("AES", CryptoPrimitive.BLOCK_CIPHER, False),
        ("SHA-256", CryptoPrimitive.HASH, False),
    ],
)
def test_quantum_vulnerable_matching(name, primitive, expected):
    asset = _asset(name=name, primitive=primitive)
    rule = _rule(quantum_vulnerable=True, match_name_patterns=["RSA", "DSA", "ECDSA", "ECDH", "DH"])
    assert rule_matches(asset, rule) is expected


def test_all_criteria_are_and():
    asset_short = _asset(name="RSA", primitive=CryptoPrimitive.PKE, key_size_bits=1024)
    asset_long = _asset(name="RSA", primitive=CryptoPrimitive.PKE, key_size_bits=4096)
    rule = _rule(
        match_name_patterns=["RSA"],
        match_primitive=CryptoPrimitive.PKE,
        match_min_key_size_bits=2048,
    )
    assert rule_matches(asset_short, rule) is True
    assert rule_matches(asset_long, rule) is False


def _seeded_rule_ids_matching(component):
    [asset] = parse_crypto_components([component])
    stored = CryptoAsset(project_id="p", scan_id="s", **asset.model_dump())
    return {rule.rule_id for rule in load_seed_rules() if rule.enabled and rule_matches(stored, rule)}


def _algorithm(name, primitive, **properties):
    return {
        "type": "cryptographic-asset",
        "bom-ref": f"crypto/{name}",
        "name": name,
        "cryptoProperties": {
            "assetType": "algorithm",
            "algorithmProperties": {"primitive": primitive, **properties},
        },
    }


@pytest.mark.parametrize(
    "component,expected",
    [
        (
            _algorithm("RSA-1024", "pke", parameterSetIdentifier="1024"),
            {"nist-131a-rsa-min-2048", "pqc-quantum-vulnerable-pke"},
        ),
        (
            _algorithm("rsa1024", "pke", parameterSetIdentifier="1024"),
            {"nist-131a-rsa-min-2048", "pqc-quantum-vulnerable-pke"},
        ),
        (_algorithm("SHA1withRSA", "signature"), {"pqc-quantum-vulnerable-pke"}),
        (_algorithm("ECDSA-P256", "signature", curve="secp256r1"), {"pqc-quantum-vulnerable-pke"}),
        (_algorithm("ECDH", "key-agree"), {"pqc-quantum-vulnerable-pke"}),
        (_algorithm("X25519", "key-agree"), {"pqc-quantum-vulnerable-pke"}),
        (_algorithm("ML-DSA-65", "signature"), set()),
        (_algorithm("SLH-DSA-SHA2-128s", "signature"), set()),
        (_algorithm("AES-256-GCM", "ae"), set()),
    ],
    ids=lambda value: value["name"] if isinstance(value, dict) else None,
)
def test_seeded_rules_match_full_cyclonedx_algorithm_names(component, expected):
    assert _seeded_rule_ids_matching(component) == expected


def test_a_family_name_token_matches_a_bare_pattern():
    assert _seeded_rule_ids_matching(_algorithm("DES-CBC", "block-cipher")) == {"nist-131a-des"}


@pytest.mark.parametrize("name", ["SHA1withRSA", "ECDH-RSA"])
def test_a_glob_pattern_keeps_whole_name_semantics(name):
    assert rule_matches(_asset(name=name), _rule(match_name_patterns=["RSA*"])) is False


def test_a_rule_without_subject_criteria_covers_no_asset():
    rule = _rule(finding_type=FindingType.CRYPTO_WEAK_PROTOCOL, match_cipher_weaknesses=["weak-cipher-rc4"])
    asset = _asset(name="AES", primitive=CryptoPrimitive.BLOCK_CIPHER)

    assert asset_in_rule_scope(asset, rule) is False
    assert rule_matches(asset, rule) is False
