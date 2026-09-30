"""normalize_crypto rehydrates the finding dicts our crypto rule analyzers build."""

import pytest
from pydantic import ValidationError

from app.models.crypto_asset import CryptoAsset
from app.models.finding import FindingType, Severity
from app.schemas.cbom import CryptoAssetType, CryptoPrimitive
from app.schemas.crypto_policy import CryptoPolicySource, CryptoRule
from app.services.aggregation import ResultAggregator
from app.services.analyzers.crypto.base import crypto_findings_for_assets

_MD5 = CryptoAsset(
    project_id="p",
    scan_id="s",
    bom_ref="crypto/md5",
    name="MD5",
    asset_type=CryptoAssetType.ALGORITHM,
    primitive=CryptoPrimitive.HASH,
)
_MD5_RULE = CryptoRule(
    rule_id="md5",
    name="MD5",
    description="MD5 is broken",
    finding_type=FindingType.CRYPTO_WEAK_ALGORITHM,
    default_severity=Severity.HIGH,
    source=CryptoPolicySource.CUSTOM,
    match_name_patterns=["MD5"],
)


def test_analyzer_findings_become_findings():
    agg = ResultAggregator()
    agg.aggregate(
        "crypto_weak_algorithm",
        {"findings": crypto_findings_for_assets([_MD5], [_MD5_RULE], scanner="crypto_weak_algorithm")},
    )
    assert [(f.id, f.severity) for f in agg.get_findings()] == [("CRYPTO-crypto_weak_algorithm-crypto/md5", "HIGH")]


def test_a_finding_our_analyzer_built_wrong_fails_the_result():
    (finding,) = crypto_findings_for_assets([_MD5], [_MD5_RULE], scanner="crypto_weak_algorithm")
    with pytest.raises(ValidationError):
        ResultAggregator().aggregate("crypto_weak_algorithm", {"findings": [{**finding, "type": "crypto_md5"}]})
