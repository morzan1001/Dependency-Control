"""The frameworks share base's `_classify` and `_waiver_reasons` instead of keeping copies."""

from app.schemas.compliance import ControlStatus, EvaluationCoverage
from app.services.compliance.frameworks import base, cve_remediation_sla, license_audit

_COMPLETE = EvaluationCoverage()


def test_classify_is_shared_from_base():
    assert license_audit._classify is base._classify
    assert cve_remediation_sla._classify is base._classify


def test_waiver_reasons_is_shared_from_base():
    assert license_audit._waiver_reasons is base._waiver_reasons
    assert cve_remediation_sla._waiver_reasons is base._waiver_reasons


def test_classify_behavior_preserved():
    assert base._classify([], _COMPLETE) == (ControlStatus.PASSED, [], None)

    active = [{"_id": "a1", "waived": False}]
    assert base._classify(active, _COMPLETE) == (ControlStatus.FAILED, ["a1"], None)

    waived = [{"id": "w1", "waived": True}]
    assert base._classify(waived, _COMPLETE) == (ControlStatus.WAIVED, ["w1"], None)


def test_waiver_reasons_keep_only_the_reasons_given_on_waived_findings():
    findings = [
        {"_id": "w1", "waived": True, "waiver_reason": "risk accepted"},
        {"_id": "w2", "waived": True, "waiver_reason": None},
        {"_id": "w3", "waived": True, "waiver_reason": ""},
        {"_id": "a1", "waived": False, "waiver_reason": "expired waiver"},
    ]

    assert base._waiver_reasons(findings) == ["risk accepted"]
