import pytest

from app.models.crypto_asset import CryptoAsset
from app.models.finding import FindingType
from app.schemas.cbom import CryptoAssetType, CryptoPrimitive
from app.schemas.recommendation import Priority, RecommendationType
from app.services.analyzers.crypto.base import crypto_findings_for_assets
from app.services.crypto_policy.seeder import load_seed_rules
from app.services.recommendation.crypto import _CRYPTO_CARDS, process_crypto


def _md5_findings():
    md5 = CryptoAsset(
        project_id="p",
        scan_id="s",
        bom_ref="crypto/algorithm/md5",
        name="MD5",
        asset_type=CryptoAssetType.ALGORITHM,
        primitive=CryptoPrimitive.HASH,
    )
    return crypto_findings_for_assets([md5], load_seed_rules(), scanner="crypto_weak_algorithm")


def test_every_crypto_finding_type_has_a_card():
    assert set(_CRYPTO_CARDS) == {t for t in FindingType if t.value.startswith("crypto_")}


def test_the_weak_algorithm_card_reads_its_table_row():
    findings = _md5_findings()

    (rec,) = process_crypto(findings)

    assert len(findings) == 1
    assert rec.type == RecommendationType.REPLACE_WEAK_ALGORITHM
    assert rec.effort == "medium"
    assert rec.priority == Priority(findings[0]["severity"].lower())
    assert rec.title == "Replace weak algorithm: MD5"
    assert rec.description == (
        "MD5 is broken or disallowed by crypto policy in 1 location. "
        "Replace it with a modern primitive in the affected components."
    )
    assert rec.action["suggested_replacement"] == "SHA-256 or SHA-3"


def test_the_action_names_every_rule_that_matched_the_asset_not_only_the_lead():
    findings = _md5_findings()
    matched = sorted({entry["rule_id"] for f in findings for entry in f["details"]["matched_rules"]})

    (rec,) = process_crypto(findings)

    assert len(matched) > 1
    assert rec.action["rule_ids"] == matched


@pytest.mark.parametrize(
    ("name", "primitive", "bits", "suggested"),
    [
        ("ECDSA", CryptoPrimitive.SIGNATURE, 160, "increase from 160 bits per policy"),
        ("RSA-2048", CryptoPrimitive.PKE, 1024, "≥3072-bit (currently 1024)"),
    ],
)
def test_only_rsa_and_dsa_keys_are_told_to_reach_3072_bits(name, primitive, bits, suggested):
    asset = CryptoAsset(
        project_id="p",
        scan_id="s",
        bom_ref=f"crypto/algorithm/{name}",
        name=name,
        asset_type=CryptoAssetType.ALGORITHM,
        primitive=primitive,
        key_size_bits=bits,
    )
    findings = crypto_findings_for_assets([asset], load_seed_rules(), scanner="crypto_weak_key")

    [rec] = process_crypto([f for f in findings if f["type"] == FindingType.CRYPTO_WEAK_KEY])

    assert rec.action["suggested_replacement"] == suggested
