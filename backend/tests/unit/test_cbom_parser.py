import json
from pathlib import Path

from app.models.crypto_asset import CryptoAsset
from app.schemas.cbom import CryptoAssetType, CryptoPrimitive
from app.services.analysis.registry import crypto_evaluators
from app.services.cbom_parser import parse_cbom, parse_crypto_components
from app.services.crypto_policy.resolver import EffectivePolicy
from app.services.crypto_policy.seeder import load_seed_rules
from tests.helpers.analyzers import bundled_iana_catalog

FIXTURES = Path(__file__).parent.parent / "fixtures" / "cbom"


def _load(name):
    with open(FIXTURES / name) as f:
        return json.load(f)


def test_parse_legacy_crypto_mixed_counts():
    assert len(parse_cbom(_load("legacy_crypto_mixed.json"))) == 3


def test_parse_legacy_md5_algorithm_details():
    md5 = next(a for a in parse_cbom(_load("legacy_crypto_mixed.json")) if a.name == "MD5")
    assert md5.asset_type == CryptoAssetType.ALGORITHM
    assert md5.primitive == CryptoPrimitive.HASH
    assert md5.key_size_bits == 128


def test_parse_legacy_rsa1024_key_size():
    rsa = next(a for a in parse_cbom(_load("legacy_crypto_mixed.json")) if a.name == "RSA")
    assert rsa.key_size_bits == 1024
    assert rsa.primitive == CryptoPrimitive.PKE
    assert rsa.padding == "PKCS1v15"


def test_parse_protocol_tls10():
    tls = next(a for a in parse_cbom(_load("legacy_crypto_mixed.json")) if a.asset_type == CryptoAssetType.PROTOCOL)
    assert tls.protocol_type == "tls"
    assert tls.version == "1.0"
    assert "TLS_RSA_WITH_RC4_128_SHA" in tls.cipher_suites


def test_parse_modern_crypto_no_weak_algos():
    assets = parse_cbom(_load("modern_crypto.json"))
    assert len(assets) == 3
    key_sizes = {a.key_size_bits for a in assets if a.key_size_bits}
    assert 256 in key_sizes
    assert 4096 in key_sizes


def test_two_cbomkit_theia_runs_over_one_tree_give_the_same_crypto_findings():
    """theia draws every bom-ref at random per run; the two fixtures are two runs over the same files."""
    rules = load_seed_rules()
    policy = EffectivePolicy(rules=rules, system_rules=rules, system_version=1, override_version=None)
    evaluators = crypto_evaluators(bundled_iana_catalog()).values()

    def findings(fixture: str) -> set[tuple[str, str]]:
        assets = [CryptoAsset(project_id="p", scan_id="s", **a.model_dump()) for a in parse_cbom(_load(fixture))]
        return {(f["id"], f["component"]) for evaluate in evaluators for f in evaluate(assets, policy)["findings"]}

    run_a, run_b = findings("cbomkit_theia_run_a.json"), findings("cbomkit_theia_run_b.json")

    assert run_a
    assert run_a == run_b


def test_references_between_assets_survive_the_content_refs():
    by_name = {a.name: a for a in parse_cbom(_load("cbomkit_theia_run_a.json")) if a.asset_type != "algorithm"}
    by_ref = {a.bom_ref: a for a in parse_cbom(_load("cbomkit_theia_run_a.json"))}
    certificate, public_key = (
        by_name["b1-test"],
        next(a for a in by_ref.values() if a.asset_type == "related-crypto-material" and a.algorithm_ref),
    )

    assert by_ref[certificate.signature_algorithm_ref].name == "SHA256-RSA"
    assert by_ref[certificate.subject_public_key_ref] == public_key
    assert by_ref[public_key.algorithm_ref].name == "RSA"


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


def test_related_crypto_material_carries_its_size_and_algorithm_ref():
    parsed = parse_crypto_components(
        [
            {
                "type": "cryptographic-asset",
                "bom-ref": "pubkey",
                "name": "public key",
                "cryptoProperties": {
                    "assetType": "related-crypto-material",
                    "relatedCryptoMaterialProperties": {"type": "public-key", "size": 1024, "algorithmRef": "rsa"},
                },
            }
        ]
    )
    (key,) = parsed
    assert (key.asset_type, key.key_size_bits, key.algorithm_ref) == (
        CryptoAssetType.RELATED_CRYPTO_MATERIAL,
        1024,
        "rsa",
    )


def test_cipher_suite_code_points_are_kept_in_the_catalog_spelling():
    suites = [
        {"name": "A", "identifiers": ["0xC0", "0x30"]},
        {"name": "B", "identifiers": ["0xc0,0x30"]},
        {"name": ""},
        {"name": "C", "identifiers": ["0xC030"]},
        "D",
        {"name": "E", "identifiers": ["0x13"]},
    ]
    (proto,) = parse_crypto_components(
        [
            {
                "type": "cryptographic-asset",
                "bom-ref": "proto",
                "name": "TLS",
                "cryptoProperties": {"assetType": "protocol", "protocolProperties": {"cipherSuites": suites}},
            }
        ]
    )
    assert proto.cipher_suites == ["A", "B", "C", "D", "E"]
    assert proto.cipher_suite_ids == ["0xC0,0x30", "0xC0,0x30", "0xC0,0x30", None, None]


def _rsa_component(**fields) -> dict:
    rsa = next(c for c in _load("legacy_crypto_mixed.json")["components"] if c["bom-ref"] == "algo-rsa1024")
    return {**rsa, **fields}


def test_a_malformed_property_entry_drops_only_that_entry():
    comp = _rsa_component(properties=["bad", {"name": "key_size", "value": "2048"}, {"name": "note", "value": ""}])

    [asset] = parse_crypto_components([comp])

    assert asset.properties == {"key_size": "2048"}


def test_repeated_occurrence_locations_are_kept_once_in_order():
    occurrences = [{"location": "b.py"}, {"location": "a.py"}, "bad", {"location": "b.py"}, {"line": 3}]

    [asset] = parse_crypto_components([_rsa_component(evidence={"occurrences": occurrences})])

    assert asset.occurrence_locations == ["b.py", "a.py"]
