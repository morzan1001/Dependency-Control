import json
from pathlib import Path


from app.schemas.cbom import CryptoAssetType, CryptoPrimitive
from app.services.cbom_parser import parse_cbom, parse_crypto_components

FIXTURES = Path(__file__).parent.parent / "fixtures" / "cbom"


def _load(name):
    with open(FIXTURES / name) as f:
        return json.load(f)


def test_parse_legacy_crypto_mixed_counts():
    cbom = parse_cbom(_load("legacy_crypto_mixed.json"))
    assert cbom.parsed_components == 3
    assert cbom.skipped_components == 0
    assert len(cbom.assets) == 3


def test_parse_legacy_md5_algorithm_details():
    cbom = parse_cbom(_load("legacy_crypto_mixed.json"))
    md5 = next(a for a in cbom.assets if a.name == "MD5")
    assert md5.asset_type == CryptoAssetType.ALGORITHM
    assert md5.primitive == CryptoPrimitive.HASH
    assert md5.key_size_bits == 128


def test_parse_legacy_rsa1024_key_size():
    cbom = parse_cbom(_load("legacy_crypto_mixed.json"))
    rsa = next(a for a in cbom.assets if a.bom_ref == "algo-rsa1024")
    assert rsa.key_size_bits == 1024
    assert rsa.primitive == CryptoPrimitive.PKE
    assert rsa.padding == "PKCS1v15"


def test_parse_protocol_tls10():
    cbom = parse_cbom(_load("legacy_crypto_mixed.json"))
    tls = next(a for a in cbom.assets if a.asset_type == CryptoAssetType.PROTOCOL)
    assert tls.protocol_type == "tls"
    assert tls.version == "1.0"
    assert "TLS_RSA_WITH_RC4_128_SHA" in tls.cipher_suites


def test_parse_modern_crypto_no_weak_algos():
    cbom = parse_cbom(_load("modern_crypto.json"))
    assert cbom.parsed_components == 3
    key_sizes = {a.key_size_bits for a in cbom.assets if a.key_size_bits}
    assert 256 in key_sizes
    assert 4096 in key_sizes


def test_parse_crypto_components_extracts_from_sbom():
    doc = _load("cyclonedx_1_6_with_crypto_assets.json")
    assets = parse_crypto_components(doc["components"])
    assert len(assets) == 1
    assert assets[0].name == "SHA-1"


def test_missing_crypto_properties_is_skipped():
    components = [
        {"type": "cryptographic-asset", "bom-ref": "r", "name": "X"},
    ]
    assets = parse_crypto_components(components)
    assert assets == []


def test_unknown_primitive_falls_back_to_other():
    components = [
        {
            "type": "cryptographic-asset",
            "bom-ref": "r",
            "name": "X",
            "cryptoProperties": {
                "assetType": "algorithm",
                "algorithmProperties": {"primitive": "quantum-magic"},
            },
        }
    ]
    assets = parse_crypto_components(components)
    assert len(assets) == 1
    assert assets[0].primitive == CryptoPrimitive.OTHER


def test_missing_bom_ref_synthesized():
    components = [
        {
            "type": "cryptographic-asset",
            "name": "MD5",
            "cryptoProperties": {
                "assetType": "algorithm",
                "algorithmProperties": {"primitive": "hash"},
            },
        }
    ]
    assets = parse_crypto_components(components)
    assert len(assets) == 1
    assert assets[0].bom_ref


def test_cipher_suites_object_shape_extracts_name():
    """CycloneDX 1.6 defines cipherSuites as objects; parser must extract name."""
    components = [
        {
            "type": "cryptographic-asset",
            "bom-ref": "proto",
            "name": "TLS",
            "cryptoProperties": {
                "assetType": "protocol",
                "protocolProperties": {
                    "type": "tls",
                    "version": "1.2",
                    "cipherSuites": [
                        {
                            "name": "TLS_RSA_WITH_RC4_128_SHA",
                            "algorithms": ["algo-rsa"],
                            "identifiers": ["0x00,0x05"],
                        },
                        "TLS_LEGACY_STRING",
                    ],
                },
            },
        }
    ]
    assets = parse_crypto_components(components)
    assert assets[0].cipher_suites == [
        "TLS_RSA_WITH_RC4_128_SHA",
        "TLS_LEGACY_STRING",
    ]


def test_cipher_suites_falsy_names_filtered():
    """Objects without a usable name must not produce dict-repr garbage."""
    components = [
        {
            "type": "cryptographic-asset",
            "bom-ref": "proto",
            "name": "TLS",
            "cryptoProperties": {
                "assetType": "protocol",
                "protocolProperties": {
                    "type": "tls",
                    "cipherSuites": [
                        {"algorithms": ["algo-rsa"]},
                        {"name": ""},
                        {"name": "TLS_GOOD_SUITE"},
                    ],
                },
            },
        }
    ]
    assets = parse_crypto_components(components)
    assert assets[0].cipher_suites == ["TLS_GOOD_SUITE"]


def test_tool_metadata_list_shape():
    cbom = parse_cbom(
        {
            "specVersion": "1.6",
            "metadata": {"tools": [{"name": "cbomkit", "version": "1.2.3"}]},
            "components": [],
        }
    )
    assert cbom.tool_name == "cbomkit"
    assert cbom.tool_version == "1.2.3"


def test_tool_metadata_dict_components_shape():
    cbom = parse_cbom(
        {
            "specVersion": "1.6",
            "metadata": {
                "tools": {"components": [{"name": "cdxgen", "version": "9.0.0"}]}
            },
            "components": [],
        }
    )
    assert cbom.tool_name == "cdxgen"
    assert cbom.tool_version == "9.0.0"


def test_tool_metadata_absent_is_none():
    cbom = parse_cbom({"specVersion": "1.6", "components": []})
    assert cbom.tool_name is None
    assert cbom.tool_version is None


def test_invalid_not_valid_after_is_none():
    components = [
        {
            "type": "cryptographic-asset",
            "bom-ref": "cert",
            "name": "cert",
            "cryptoProperties": {
                "assetType": "certificate",
                "certificateProperties": {
                    "subjectName": "CN=x",
                    "notValidAfter": "not-a-date",
                },
            },
        }
    ]
    assets = parse_crypto_components(components)
    assert assets[0].not_valid_after is None
