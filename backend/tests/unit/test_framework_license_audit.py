"""Unit tests for LicenseAuditFramework."""

import pytest

from app.services.analytics.scopes import ResolvedScope
from app.services.compliance.frameworks.base import EvaluationInput
from app.services.compliance.frameworks.license_audit import LicenseAuditFramework


def _eval_input(findings=None, policy=None):
    return EvaluationInput(
        resolved=ResolvedScope(scope="project", scope_id="p", project_ids=["p"]),
        scope_description="project 'p'",
        crypto_assets=[],
        findings=findings or [],
        policy_rules=[policy] if policy is not None else [],
        policy_version=1,
        iana_catalog_version=1,
        scan_ids=["s1"],
    )


def test_sync_evaluate_raises_runtime_error():
    fw = LicenseAuditFramework()
    with pytest.raises(RuntimeError, match="async-only"):
        fw.evaluate(_eval_input())


@pytest.mark.asyncio
async def test_no_findings_all_controls_pass():
    fw = LicenseAuditFramework()
    policy = {"allow_strong_copyleft": False, "allow_network_copyleft": False}
    result = await fw.evaluate_async(_eval_input(findings=[], policy=policy))
    assert result.summary["failed"] == 0
    assert result.summary["total"] == 3  # strong + network + unknown-license controls


@pytest.mark.asyncio
async def test_strong_copyleft_violation_fails():
    fw = LicenseAuditFramework()
    policy = {"allow_strong_copyleft": False, "allow_network_copyleft": False}
    findings = [
        {
            "_id": "f1",
            "type": "license",
            "details": {"license_category": "strong_copyleft"},
            "waived": False,
        }
    ]
    result = await fw.evaluate_async(_eval_input(findings=findings, policy=policy))
    failed = [c for c in result.controls if c.status == "failed"]
    assert any(c.control_id == "LICENSE-AUDIT-STRONG-COPYLEFT" for c in failed)


@pytest.mark.asyncio
async def test_allowed_category_is_not_applicable():
    fw = LicenseAuditFramework()
    policy = {"allow_strong_copyleft": True, "allow_network_copyleft": False}
    findings = [
        {
            "_id": "f1",
            "type": "license",
            "details": {"license_category": "strong_copyleft"},
            "waived": False,
        }
    ]
    result = await fw.evaluate_async(_eval_input(findings=findings, policy=policy))
    strong_ctrl = next(c for c in result.controls if c.control_id == "LICENSE-AUDIT-STRONG-COPYLEFT")
    assert strong_ctrl.status == "not_applicable"


@pytest.mark.asyncio
async def test_waived_finding_produces_waived_control():
    fw = LicenseAuditFramework()
    policy = {"allow_strong_copyleft": False}
    findings = [
        {
            "_id": "f1",
            "type": "license",
            "details": {"license_category": "strong_copyleft"},
            "waived": True,
            "waiver_reason": "accepted risk",
        }
    ]
    result = await fw.evaluate_async(_eval_input(findings=findings, policy=policy))
    strong_ctrl = next(c for c in result.controls if c.control_id == "LICENSE-AUDIT-STRONG-COPYLEFT")
    assert strong_ctrl.status == "waived"
    assert "accepted risk" in strong_ctrl.waiver_reasons
