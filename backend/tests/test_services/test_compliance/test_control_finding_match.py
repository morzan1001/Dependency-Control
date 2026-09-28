"""Which findings count as evidence against a control."""

from app.models.finding import FindingType, Severity
from app.schemas.compliance import ControlDefinition
from app.services.compliance.frameworks.base import _finding_matches_control

_RULE_ID = "bsi-02102-tls-min-12"


def _control(**kwargs) -> ControlDefinition:
    return ControlDefinition(
        control_id="BSI-02102-" + _RULE_ID,
        title="TLS 1.2 minimum",
        description="",
        severity=Severity.HIGH,
        remediation="",
        **kwargs,
    )


def test_a_rule_retyped_since_the_seed_still_counts_against_its_control():
    """The control's types come from the seed; matching on them hid a retyped rule and reported PASSED."""
    control = _control(maps_to_rule_ids=[_RULE_ID], maps_to_finding_types=[FindingType.CRYPTO_WEAK_ALGORITHM])
    finding = {"type": "crypto_weak_key", "details": {"rule_id": _RULE_ID}}

    assert _finding_matches_control(finding, control)


def test_a_finding_of_another_rule_does_not_count():
    control = _control(maps_to_rule_ids=[_RULE_ID], maps_to_finding_types=[FindingType.CRYPTO_WEAK_ALGORITHM])

    assert not _finding_matches_control({"type": "crypto_weak_algorithm", "details": {"rule_id": "x"}}, control)


def test_a_control_without_rule_ids_matches_by_finding_type():
    control = _control(maps_to_finding_types=[FindingType.CRYPTO_CERT_EXPIRED])

    assert _finding_matches_control({"type": "crypto_cert_expired"}, control)
    assert not _finding_matches_control({"type": "crypto_weak_key"}, control)
