"""What a crypto policy write accepts. Every refused rule would otherwise be stored under a 200 and
then never run, fire on every asset, or mis-grade what it matches."""

import pytest
from pydantic import ValidationError

from app.schemas.crypto_policy import CryptoPolicyPutRequest
from app.services.crypto_policy.seeder import load_seed_rules


def _rule(rule_id: str = "r1", **fields) -> dict:
    return {
        "rule_id": rule_id,
        "name": rule_id,
        "description": "",
        "finding_type": "crypto_weak_algorithm",
        "default_severity": "HIGH",
        "source": "custom",
        "match_primitive": "hash",
        "match_name_patterns": ["MD5"],
        **fields,
    }


def _refused(*rules: dict) -> str:
    with pytest.raises(ValidationError) as exc:
        CryptoPolicyPutRequest(rules=list(rules))
    return str(exc.value)


def test_every_seeded_rule_is_accepted():
    CryptoPolicyPutRequest(rules=[rule.model_dump() for rule in load_seed_rules()])


def test_a_misspelled_rule_key_is_refused():
    """Dropped silently, the rule stored without its name filter flagged every hash asset."""
    assert "match_name_pattern" in _refused(_rule(match_name_pattern=["md5"]))


@pytest.mark.parametrize(
    "fields",
    [
        {"match_primitive": None, "match_name_patterns": []},
        {"match_primitive": None, "match_name_patterns": [], "match_min_key_size_bits": 2048},
    ],
)
def test_a_rule_driven_rule_without_a_subject_matcher_is_refused(fields):
    """It would flag every crypto asset, AES-256 and TLS 1.3 included."""
    assert "'r1'" in _refused(_rule(**fields))


def test_a_disabled_rule_is_not_held_to_what_an_analyzer_evaluates():
    """A disabled rule never runs, so a legacy one must not block every later save of its policy."""
    CryptoPolicyPutRequest(rules=[_rule(enabled=False, match_primitive=None, match_name_patterns=[])])


def test_a_disabled_rule_still_respects_the_list_bound():
    assert "'r1'" in _refused(_rule(enabled=False, match_name_patterns=[f"p{index}" for index in range(51)]))


@pytest.mark.parametrize(
    ("finding_type", "fields"),
    [
        (
            "crypto_weak_protocol",
            {"match_primitive": None, "match_name_patterns": [], "match_protocol_versions": ["tls1.0"]},
        ),
        ("crypto_cert_expired", {}),
        ("crypto_weak_algorithm", {"match_name_patterns": [], "expiry_high_days": 30}),
        (
            "crypto_cert_expiring_soon",
            {"match_primitive": None, "match_name_patterns": [], "validity_too_long_days": 398},
        ),
        (
            "crypto_weak_key",
            {"match_primitive": None, "match_name_patterns": [], "match_cipher_weaknesses": ["no-pfs"]},
        ),
    ],
)
def test_a_finding_type_no_analyzer_evaluates_for_the_rule_is_refused(finding_type, fields):
    assert "'r1'" in _refused(_rule(finding_type=finding_type, **fields))


def test_an_inverted_expiry_ladder_is_refused():
    lifecycle = {"finding_type": "crypto_cert_expiring_soon", "match_primitive": None, "match_name_patterns": []}

    assert "'r1'" in _refused(_rule(expiry_critical_days=90, expiry_high_days=30, **lifecycle))
    CryptoPolicyPutRequest(rules=[_rule(expiry_critical_days=7, expiry_high_days=7, expiry_low_days=90, **lifecycle)])


@pytest.mark.parametrize("ids", [("x", "x"), ("", "y")])
def test_duplicate_or_empty_rule_ids_are_refused(ids):
    """Rules are keyed by rule_id downstream, so a duplicate silently disarms the first one."""
    assert "duplicate or empty rule_id" in _refused(*(_rule(rule_id) for rule_id in ids))


def test_the_rule_count_and_each_list_matcher_are_bounded():
    assert "200" in _refused(*(_rule(f"r{index}") for index in range(201)))
    assert "more than 50 entries" in _refused(_rule(match_name_patterns=[f"p{index}" for index in range(51)]))


def test_a_policy_at_the_rule_and_list_bounds_is_accepted():
    CryptoPolicyPutRequest(rules=[_rule(f"r{index}") for index in range(200)])
    CryptoPolicyPutRequest(rules=[_rule(match_name_patterns=[f"p{index}" for index in range(50)])])
