"""Elegance #48: `_classify` and `_waiver_reason` must be the single shared
implementations in frameworks/base.py, imported (not re-defined) by both
license_audit and cve_remediation_sla.

Before the dedup, each framework defined its own copy of these helpers, so the
`is` identity checks below failed. After the move they resolve to the exact
same function objects, and behavior stays byte-for-byte identical.
"""

from app.schemas.compliance import ControlStatus
from app.services.compliance.frameworks import base, cve_remediation_sla, license_audit


def test_classify_is_shared_from_base():
    assert license_audit._classify is base._classify
    assert cve_remediation_sla._classify is base._classify


def test_waiver_reason_is_shared_from_base():
    assert license_audit._waiver_reason is base._waiver_reason
    assert cve_remediation_sla._waiver_reason is base._waiver_reason


def test_classify_behavior_preserved():
    # empty -> PASSED, no evidence
    assert base._classify([]) == (ControlStatus.PASSED, [])

    # active (non-waived) finding -> FAILED, evidence collected
    active = [{"_id": "a1", "waived": False}]
    assert base._classify(active) == (ControlStatus.FAILED, ["a1"])

    # all waived -> WAIVED, evidence still collected
    waived = [{"id": "w1", "waived": True}]
    assert base._classify(waived) == (ControlStatus.WAIVED, ["w1"])

    # evidence only for findings carrying an id/_id
    mixed = [{"_id": "a1", "waived": True}, {"waived": True}]
    assert base._classify(mixed) == (ControlStatus.WAIVED, ["a1"])


def test_waiver_reason_behavior_preserved():
    assert base._waiver_reason({"waiver_reason": "risk accepted"}) == "risk accepted"
    assert base._waiver_reason({"waiver_reason": None}) == ""
    assert base._waiver_reason({}) == ""
