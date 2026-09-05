"""`_classify` and `_waiver_reason` must be the single shared implementations in frameworks/base.py, imported by both license_audit and cve_remediation_sla."""

from app.schemas.compliance import ControlStatus, EvaluationCoverage
from app.services.compliance.frameworks import base, cve_remediation_sla, license_audit

_EVALUATED = 12
_COMPLETE = EvaluationCoverage(findings_evaluated=_EVALUATED, findings_in_scope=_EVALUATED, limit=_EVALUATED)


def test_classify_is_shared_from_base():
    assert license_audit._classify is base._classify
    assert cve_remediation_sla._classify is base._classify


def test_waiver_reason_is_shared_from_base():
    assert license_audit._waiver_reason is base._waiver_reason
    assert cve_remediation_sla._waiver_reason is base._waiver_reason


def test_classify_behavior_preserved():
    assert base._classify([], _COMPLETE) == (ControlStatus.PASSED, [], None)

    active = [{"_id": "a1", "waived": False}]
    assert base._classify(active, _COMPLETE) == (ControlStatus.FAILED, ["a1"], None)

    waived = [{"id": "w1", "waived": True}]
    assert base._classify(waived, _COMPLETE) == (ControlStatus.WAIVED, ["w1"], None)

    # Evidence is collected only for findings carrying an id/_id.
    mixed = [{"_id": "a1", "waived": True}, {"waived": True}]
    assert base._classify(mixed, _COMPLETE) == (ControlStatus.WAIVED, ["a1"], None)


def test_waiver_reason_behavior_preserved():
    assert base._waiver_reason({"waiver_reason": "risk accepted"}) == "risk accepted"
    assert base._waiver_reason({"waiver_reason": None}) == ""
    assert base._waiver_reason({}) == ""
