import pytest

from app.models.crypto_asset import CryptoAsset
from app.models.finding import FindingType, Severity
from app.schemas.cbom import CryptoAssetType, CryptoPrimitive
from app.schemas.crypto_policy import CryptoPolicySource, CryptoRule
from app.services.analyzers.crypto.matcher import rule_matches


def _asset(**kw):
    defaults = dict(
        project_id="p", scan_id="s", bom_ref="r",
        name="X", asset_type=CryptoAssetType.ALGORITHM,
    )
    defaults.update(kw)
    return CryptoAsset(**defaults)


def _rule(**kw):
    defaults = dict(
        rule_id="r", name="n", description="",
        finding_type=FindingType.CRYPTO_WEAK_ALGORITHM,
        default_severity=Severity.HIGH,
        source=CryptoPolicySource.NIST_SP_800_131A,
    )
    defaults.update(kw)
    return CryptoRule(**defaults)


@pytest.mark.parametrize("name,patterns,expected", [
    ("MD5", ["MD5"], True),
    ("md5", ["MD5"], True),
    ("MD-5", ["MD*"], True),
    ("SHA-256", ["MD5", "SHA-1"], False),
])
def test_name_pattern_matching(name, patterns, expected):
    asset = _asset(name=name)
    rule = _rule(match_name_patterns=patterns)
    assert rule_matches(asset, rule) is expected


@pytest.mark.parametrize("asset_name,variant,patterns,expected", [
    ("generic", "RSA-2048", ["RSA*"], True),
    ("generic", None, ["RSA*"], False),
])
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


@pytest.mark.parametrize("key_size,threshold,expected", [
    (1024, 2048, True),
    (2048, 2048, False),
    (4096, 2048, False),
    (None, 2048, False),
])
def test_min_key_size_matching(key_size, threshold, expected):
    asset = _asset(name="RSA", key_size_bits=key_size)
    rule = _rule(match_name_patterns=["RSA"], match_min_key_size_bits=threshold)
    assert rule_matches(asset, rule) is expected


@pytest.mark.parametrize("proto,version,match_list,expected", [
    ("tls", "1.0", ["tls 1.0", "tls 1.1"], True),
    ("tls", "1.2", ["tls 1.0", "tls 1.1"], False),
    ("TLS", "1.0", ["tls 1.0"], True),
])
def test_protocol_version_matching(proto, version, match_list, expected):
    asset = _asset(
        asset_type=CryptoAssetType.PROTOCOL,
        protocol_type=proto, version=version,
    )
    rule = _rule(match_protocol_versions=match_list)
    assert rule_matches(asset, rule) is expected


@pytest.mark.parametrize("name,primitive,expected", [
    ("RSA", CryptoPrimitive.PKE, True),
    ("ECDSA", CryptoPrimitive.SIGNATURE, True),
    ("DH", CryptoPrimitive.KEM, True),
    ("AES", CryptoPrimitive.BLOCK_CIPHER, False),
    ("SHA-256", CryptoPrimitive.HASH, False),
])
def test_quantum_vulnerable_matching(name, primitive, expected):
    asset = _asset(name=name, primitive=primitive)
    rule = _rule(quantum_vulnerable=True,
                 match_name_patterns=["RSA", "DSA", "ECDSA", "ECDH", "DH"])
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
