from app.schemas.crypto_policy import RULE_DRIVEN_FINDING_TYPES
from app.services.analysis.registry import CRYPTO_ANALYZERS, SELECTABLE_ANALYZERS, analyzer_factories
from app.services.analyzers import CryptoRuleAnalyzer


def test_every_rule_driven_finding_type_has_its_own_crypto_rule_analyzer():
    rule_analyzers = {
        name: analyzer
        for name, factory in analyzer_factories.items()
        if isinstance(analyzer := factory(), CryptoRuleAnalyzer)
    }

    assert set(rule_analyzers) == {finding_type.value for finding_type in RULE_DRIVEN_FINDING_TYPES}
    for name, analyzer in rule_analyzers.items():
        assert (analyzer.name, analyzer.finding_types) == (name, {name})


def test_the_rule_driven_analyzers_are_crypto_analyzers_a_project_cannot_select():
    names = {finding_type.value for finding_type in RULE_DRIVEN_FINDING_TYPES}

    assert names <= CRYPTO_ANALYZERS
    assert not names & SELECTABLE_ANALYZERS
