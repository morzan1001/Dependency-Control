"""Compliance applicability must be control-specific (improvement audit #2).

A control is eligible for PASSED only when at least one crypto asset falls
within the SUBJECT scope of one of the control's mapped rules. An RSA-key-size
control must NOT report PASSED on a project that contains only AES — that is a
false attestation.
"""

from app.models.crypto_asset import CryptoAsset
from app.models.finding import FindingType, Severity
from app.schemas.cbom import CryptoAssetType, CryptoPrimitive
from app.schemas.compliance import ControlDefinition, ControlStatus
from app.schemas.crypto_policy import CryptoPolicySource, CryptoRule
from app.services.analytics.scopes import ResolvedScope
from app.services.compliance.frameworks.base import (
    EvaluationInput,
    _is_applicable,
    default_evaluator,
)

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
    maps_to_finding_types=[FindingType.CRYPTO_WEAK_KEY],
)


def _asset(**kw):
    defaults = dict(project_id="p", scan_id="s", bom_ref="r", name="X", asset_type=CryptoAssetType.ALGORITHM)
    defaults.update(kw)
    return CryptoAsset(**defaults)


def _input(assets, *, findings=None):
    return EvaluationInput(
        resolved=ResolvedScope(scope="user", scope_id=None, project_ids=["p"]),
        scope_description="user 'alice'",
        crypto_assets=assets,
        findings=findings or [],
        policy_rules=[_RSA_RULE.model_dump()],
        policy_version=1,
        iana_catalog_version=1,
        scan_ids=["s1"],
    )


def test_rsa_control_not_applicable_when_only_aes_present():
    aes = _asset(name="AES", primitive=CryptoPrimitive.BLOCK_CIPHER, key_size_bits=256)
    assert _is_applicable(_RSA_CONTROL, _input([aes])) is False


def test_rsa_control_applicable_when_compliant_rsa_present():
    rsa = _asset(name="RSA", primitive=CryptoPrimitive.PKE, key_size_bits=4096)
    assert _is_applicable(_RSA_CONTROL, _input([rsa])) is True


def test_rsa_control_passes_with_compliant_rsa_and_no_findings():
    rsa = _asset(name="RSA", primitive=CryptoPrimitive.PKE, key_size_bits=4096)
    result = default_evaluator(_RSA_CONTROL, _input([rsa]))
    assert result.status == ControlStatus.PASSED


def test_rsa_control_not_applicable_with_only_aes_and_no_findings():
    aes = _asset(name="AES", primitive=CryptoPrimitive.BLOCK_CIPHER, key_size_bits=256)
    result = default_evaluator(_RSA_CONTROL, _input([aes]))
    assert result.status == ControlStatus.NOT_APPLICABLE


def test_no_assets_is_not_applicable():
    assert _is_applicable(_RSA_CONTROL, _input([])) is False


def test_fallback_to_inventory_when_no_scoping_rules_available():
    """If the control's rules aren't in the effective policy, fall back to
    inventory presence (don't hide the control)."""
    aes = _asset(name="AES", primitive=CryptoPrimitive.BLOCK_CIPHER)
    data = EvaluationInput(
        resolved=ResolvedScope(scope="user", scope_id=None, project_ids=["p"]),
        scope_description="user 'alice'",
        crypto_assets=[aes],
        findings=[],
        policy_rules=[],  # control's rule not present in policy
        policy_version=1,
        iana_catalog_version=1,
        scan_ids=["s1"],
    )
    assert _is_applicable(_RSA_CONTROL, data) is True
