"""Compliance applicability is control-specific: a control only PASSES when a crypto asset falls within one of its mapped rules' subject scope."""

from app.models.crypto_asset import CryptoAsset
from app.models.finding import FindingType, Severity
from app.schemas.cbom import CryptoAssetType, CryptoPrimitive
from app.schemas.compliance import ControlDefinition, ControlStatus
from app.schemas.crypto_policy import CryptoPolicySource, CryptoRule
from app.services.analyzers.crypto.base import crypto_findings_for_assets
from app.services.compliance.frameworks.base import (
    _Applicability,
    _applicability,
    default_evaluator,
)
from tests.helpers.compliance import evaluation_input

_RSA_RULE = CryptoRule(
    rule_id="nist-131a-rsa-min-2048",
    name="RSA keys shorter than 2048 bits are disallowed",
    description="",
    finding_type=FindingType.CRYPTO_WEAK_KEY,
    default_severity=Severity.HIGH,
    source=CryptoPolicySource.NIST_SP_800_131A,
    match_name_patterns=["RSA"],
    match_primitive=CryptoPrimitive.PKE,
    match_min_key_size_bits=2048,
)

_RSA_CONTROL = ControlDefinition(
    control_id="NIST-131A-rsa-min-2048",
    title="RSA keys >= 2048 bits",
    description="",
    severity=Severity.HIGH,
    remediation="",
    maps_to_rule_ids=["nist-131a-rsa-min-2048"],
)


def _asset(**kw):
    defaults = {"project_id": "p", "scan_id": "s", "bom_ref": "r", "name": "X", "asset_type": CryptoAssetType.ALGORITHM}
    defaults.update(kw)
    return CryptoAsset(**defaults)


def _input(assets, rules=(_RSA_RULE,), *, findings=()):
    return evaluation_input(crypto_assets=assets, findings=list(findings), policy_rules=list(rules))


def _state(control, data):
    return _applicability(control, data, [])[0]


def test_rsa_control_not_applicable_when_only_aes_present():
    aes = _asset(name="AES", primitive=CryptoPrimitive.BLOCK_CIPHER, key_size_bits=256)
    assert _state(_RSA_CONTROL, _input([aes])) is _Applicability.NO_ASSET_IN_SCOPE


def test_rsa_control_applicable_when_compliant_rsa_present():
    rsa = _asset(name="RSA", primitive=CryptoPrimitive.PKE, key_size_bits=4096)
    assert _state(_RSA_CONTROL, _input([rsa])) is _Applicability.APPLICABLE


def test_rsa_control_passes_with_compliant_rsa_and_no_findings():
    rsa = _asset(name="RSA", primitive=CryptoPrimitive.PKE, key_size_bits=4096)
    result = default_evaluator(_RSA_CONTROL, _input([rsa]))
    assert result.status == ControlStatus.PASSED


def test_rsa_control_not_applicable_with_only_aes_and_no_findings():
    aes = _asset(name="AES", primitive=CryptoPrimitive.BLOCK_CIPHER, key_size_bits=256)
    result = default_evaluator(_RSA_CONTROL, _input([aes]))
    assert result.status == ControlStatus.NOT_APPLICABLE


def test_rsa_control_applicable_when_one_of_several_assets_is_in_scope():
    """A real inventory is mixed; one matching asset makes the control evaluable, not every asset."""
    aes = _asset(name="AES", primitive=CryptoPrimitive.BLOCK_CIPHER, key_size_bits=256)
    rsa = _asset(name="RSA", primitive=CryptoPrimitive.PKE, key_size_bits=4096)
    assert _state(_RSA_CONTROL, _input([aes, rsa])) is _Applicability.APPLICABLE


def test_rsa_control_passes_on_a_mixed_inventory_with_no_findings():
    aes = _asset(name="AES", primitive=CryptoPrimitive.BLOCK_CIPHER, key_size_bits=256)
    rsa = _asset(name="RSA", primitive=CryptoPrimitive.PKE, key_size_bits=4096)
    result = default_evaluator(_RSA_CONTROL, _input([aes, rsa]))
    assert result.status == ControlStatus.PASSED


def test_rsa_control_is_not_evaluated_over_an_rsa_key_of_unknown_size():
    """rule_matches skips a sizeless key, so no finding can exist and PASSED would attest an unchecked minimum."""
    rsa = _asset(name="RSA", primitive=CryptoPrimitive.PKE)

    result = default_evaluator(_RSA_CONTROL, _input([rsa]))

    assert result.status == ControlStatus.NOT_EVALUATED
    assert "1 of 1 in-scope assets" in (result.status_reason or "")


def test_one_sizeless_rsa_key_withholds_the_verdict_beside_a_compliant_one():
    sizeless = _asset(name="RSA", primitive=CryptoPrimitive.PKE, bom_ref="r1")
    compliant = _asset(name="RSA", primitive=CryptoPrimitive.PKE, bom_ref="r2", key_size_bits=4096)

    result = default_evaluator(_RSA_CONTROL, _input([sizeless, compliant]))

    assert result.status == ControlStatus.NOT_EVALUATED
    assert "1 of 2 in-scope assets" in (result.status_reason or "")
    assert "2048-bit" in (result.status_reason or "")


def _weak_rsa_finding(*, waived):
    """The weak-key analyzer's finding for a 1024-bit RSA key, as persisted under its scan."""
    weak = _asset(name="RSA", primitive=CryptoPrimitive.PKE, bom_ref="r2", key_size_bits=1024)
    (finding,) = crypto_findings_for_assets([weak], [_RSA_RULE], scanner="crypto_weak_key")
    return finding | {"_id": f"s-{finding['id']}", "scan_id": weak.scan_id, "waived": waived}


def test_a_sizeless_rsa_key_withholds_a_waived_verdict():
    sizeless = _asset(name="RSA", primitive=CryptoPrimitive.PKE, bom_ref="r1")

    result = default_evaluator(_RSA_CONTROL, _input([sizeless], findings=[_weak_rsa_finding(waived=True)]))

    assert result.status == ControlStatus.NOT_EVALUATED


def test_an_unwaived_finding_fails_the_control_despite_a_sizeless_key():
    sizeless = _asset(name="RSA", primitive=CryptoPrimitive.PKE, bom_ref="r1")

    result = default_evaluator(_RSA_CONTROL, _input([sizeless], findings=[_weak_rsa_finding(waived=False)]))

    assert result.status == ControlStatus.FAILED


def test_no_assets_is_not_applicable():
    assert _state(_RSA_CONTROL, _input([])) is _Applicability.NO_ASSET_IN_SCOPE


def test_a_control_whose_rules_are_missing_from_the_policy_is_not_evaluated():
    """The analyzer never ran the missing rule, so no finding can exist and PASSED would be a false attestation."""
    aes = _asset(name="AES", primitive=CryptoPrimitive.BLOCK_CIPHER)
    data = _input([aes], [])
    assert _state(_RSA_CONTROL, data) is _Applicability.RULES_UNRESOLVED
    result = default_evaluator(_RSA_CONTROL, data)
    assert result.status == ControlStatus.NOT_EVALUATED
    assert "nist-131a-rsa-min-2048" in (result.status_reason or "")


# Controls backed only by disabled policy rules must never PASS.

_DISABLED_RSA_RULE = CryptoRule(
    rule_id="nist-131a-rsa-min-2048",
    name="RSA keys shorter than 2048 bits are disallowed",
    description="",
    finding_type=FindingType.CRYPTO_WEAK_KEY,
    default_severity=Severity.HIGH,
    source=CryptoPolicySource.NIST_SP_800_131A,
    match_name_patterns=["RSA"],
    match_primitive=CryptoPrimitive.PKE,
    match_min_key_size_bits=2048,
    enabled=False,
)


def test_control_backed_only_by_disabled_rule_is_not_applicable():
    """A disabled rule is never evaluated, so no finding can exist and PASSED would be a false attestation."""
    rsa = _asset(name="RSA", primitive=CryptoPrimitive.PKE, key_size_bits=4096)
    data = _input([rsa], [_DISABLED_RSA_RULE])
    assert _state(_RSA_CONTROL, data) is _Applicability.RULES_DISABLED


def test_disabled_rule_control_reports_not_applicable_not_passed():
    rsa = _asset(name="RSA", primitive=CryptoPrimitive.PKE, key_size_bits=4096)
    data = _input([rsa], [_DISABLED_RSA_RULE])
    result = default_evaluator(_RSA_CONTROL, data)
    assert result.status == ControlStatus.NOT_APPLICABLE


def test_enabled_rule_still_applicable_alongside_disabled_duplicate():
    """If at least one backing rule is enabled the control is still evaluable."""
    rsa = _asset(name="RSA", primitive=CryptoPrimitive.PKE, key_size_bits=4096)
    data = _input([rsa], [_RSA_RULE])
    assert _state(_RSA_CONTROL, data) is _Applicability.APPLICABLE


# default_evaluator must honour details.matched_rules.

_MD5_CONTROL = ControlDefinition(
    control_id="NIST-131A-md5",
    title="MD5 is disallowed",
    description="",
    severity=Severity.HIGH,
    remediation="",
    maps_to_rule_ids=["nist-131a-md5"],
)


def test_evaluator_matches_finding_via_matched_rules():
    """The NIST control must FAIL on a deduped finding that records its rule under details.matched_rules."""
    finding = {
        "id": "f1",
        "type": "crypto_weak_algorithm",
        "waived": False,
        "details": {
            "rule_id": "bsi-02102-md5",
            "matched_rules": [
                {"rule_id": "bsi-02102-md5"},
                {"rule_id": "nist-131a-md5"},
            ],
        },
    }
    data = _input([], [], findings=[finding])
    result = default_evaluator(_MD5_CONTROL, data)
    assert result.status == ControlStatus.FAILED
    assert "f1" in result.evidence_finding_ids


def test_evaluator_ignores_finding_when_no_rule_matches():
    finding = {
        "id": "f2",
        "type": "crypto_weak_algorithm",
        "waived": False,
        "details": {
            "rule_id": "bsi-02102-md5",
            "matched_rules": [{"rule_id": "bsi-02102-md5"}],
        },
    }
    data = _input([], [], findings=[finding])
    result = default_evaluator(_MD5_CONTROL, data)
    assert result.status != ControlStatus.FAILED
