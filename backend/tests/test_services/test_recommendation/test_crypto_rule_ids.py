from app.models.crypto_asset import CryptoAsset
from app.schemas.cbom import CryptoAssetType, CryptoPrimitive
from app.services.analyzers.crypto.base import crypto_findings_for_assets
from app.services.crypto_policy.seeder import load_seed_rules
from app.services.recommendation.crypto import process_crypto


def test_the_action_names_every_rule_that_matched_the_asset_not_only_the_lead():
    md5 = CryptoAsset(
        project_id="p",
        scan_id="s",
        bom_ref="crypto/algorithm/md5",
        name="MD5",
        asset_type=CryptoAssetType.ALGORITHM,
        primitive=CryptoPrimitive.HASH,
    )
    findings = crypto_findings_for_assets([md5], load_seed_rules(), scanner="crypto_weak_algorithm")
    matched = sorted({entry["rule_id"] for f in findings for entry in f["details"]["matched_rules"]})

    (rec,) = process_crypto(findings)

    assert len(matched) > 1
    assert rec.action["rule_ids"] == matched
