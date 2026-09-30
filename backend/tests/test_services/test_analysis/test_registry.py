from app.models.crypto_asset import CryptoAsset
from app.models.finding import Severity
from app.schemas.cbom import CryptoAssetType, CryptoPrimitive
from app.schemas.crypto_policy import RULE_DRIVEN_FINDING_TYPES, CryptoPolicySource, CryptoRule
from app.services.analysis.registry import CRYPTO_ANALYZERS, SELECTABLE_ANALYZERS, crypto_evaluators
from app.services.crypto_policy.resolver import EffectivePolicy


def test_every_rule_driven_finding_type_has_an_evaluator_that_emits_only_its_type():
    asset = CryptoAsset(
        project_id="p",
        scan_id="s",
        bom_ref="a",
        name="RSA",
        asset_type=CryptoAssetType.ALGORITHM,
        primitive=CryptoPrimitive.PKE,
        key_size_bits=1024,
    )
    rules = [
        CryptoRule(
            rule_id=ft.value,
            name=ft.value,
            description="",
            finding_type=ft,
            default_severity=Severity.HIGH,
            source=CryptoPolicySource.CUSTOM,
            match_name_patterns=["RSA"],
        )
        for ft in RULE_DRIVEN_FINDING_TYPES
    ]
    policy = EffectivePolicy(rules=rules, system_rules=rules, system_version=1, override_version=None)
    evaluators = crypto_evaluators({})

    for ft in RULE_DRIVEN_FINDING_TYPES:
        assert [f["type"] for f in evaluators[ft.value]([asset], policy)["findings"]] == [ft.value]


def test_the_crypto_analyzers_are_exactly_the_evaluators_and_a_project_cannot_select_them():
    assert frozenset(crypto_evaluators({})) == CRYPTO_ANALYZERS
    assert {ft.value for ft in RULE_DRIVEN_FINDING_TYPES} <= CRYPTO_ANALYZERS
    assert not CRYPTO_ANALYZERS & SELECTABLE_ANALYZERS
