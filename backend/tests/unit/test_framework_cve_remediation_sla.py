"""Unit tests for CveRemediationSlaFramework."""

from datetime import datetime, timedelta, timezone

import pytest

from app.services.analytics.scopes import ResolvedScope
from app.services.compliance.frameworks.base import EvaluationInput
from app.services.compliance.frameworks.cve_remediation_sla import CveRemediationSlaFramework


def _eval_input(findings=None):
    return EvaluationInput(
        resolved=ResolvedScope(scope="project", scope_id="p", project_ids=["p"]),
        scope_description="project 'p'",
        crypto_assets=[],
        findings=findings or [],
        policy_rules=[],
        policy_version=1,
        iana_catalog_version=1,
        scan_ids=["s1"],
    )


def test_sync_evaluate_raises_runtime_error():
    fw = CveRemediationSlaFramework()
    with pytest.raises(RuntimeError, match="async-only"):
        fw.evaluate(_eval_input())


@pytest.mark.asyncio
async def test_no_findings_all_controls_pass():
    fw = CveRemediationSlaFramework()
    result = await fw.evaluate_async(_eval_input(findings=[]))
    assert result.summary["failed"] == 0
    assert result.summary["total"] == 3  # CRITICAL / HIGH / MEDIUM buckets


@pytest.mark.asyncio
async def test_overdue_critical_vulnerability_fails():
    fw = CveRemediationSlaFramework()
    now = datetime.now(timezone.utc)
    findings = [
        {
            "_id": "f1",
            "type": "vulnerability",
            "severity": "CRITICAL",
            "first_seen_at": now - timedelta(days=10),
            "status": "open",
            "waived": False,
        }
    ]
    result = await fw.evaluate_async(_eval_input(findings=findings))
    critical = next(c for c in result.controls if c.control_id == "CVE-SLA-CRITICAL")
    assert critical.status == "failed"


@pytest.mark.asyncio
async def test_recent_critical_within_sla_passes():
    fw = CveRemediationSlaFramework()
    now = datetime.now(timezone.utc)
    findings = [
        {
            "_id": "f1",
            "type": "vulnerability",
            "severity": "CRITICAL",
            "first_seen_at": now - timedelta(days=2),  # within 7-day SLA
            "status": "open",
            "waived": False,
        }
    ]
    result = await fw.evaluate_async(_eval_input(findings=findings))
    critical = next(c for c in result.controls if c.control_id == "CVE-SLA-CRITICAL")
    assert critical.status == "passed"


@pytest.mark.asyncio
async def test_fixed_finding_does_not_fail_sla():
    fw = CveRemediationSlaFramework()
    now = datetime.now(timezone.utc)
    findings = [
        {
            "_id": "f1",
            "type": "vulnerability",
            "severity": "CRITICAL",
            "first_seen_at": now - timedelta(days=30),
            "status": "fixed",
            "waived": False,
        }
    ]
    result = await fw.evaluate_async(_eval_input(findings=findings))
    critical = next(c for c in result.controls if c.control_id == "CVE-SLA-CRITICAL")
    assert critical.status == "passed"


@pytest.mark.asyncio
async def test_waived_overdue_produces_waived_control():
    fw = CveRemediationSlaFramework()
    now = datetime.now(timezone.utc)
    findings = [
        {
            "_id": "f1",
            "type": "vulnerability",
            "severity": "HIGH",
            "first_seen_at": now - timedelta(days=60),
            "status": "open",
            "waived": True,
            "waiver_reason": "compensating control",
        }
    ]
    result = await fw.evaluate_async(_eval_input(findings=findings))
    high = next(c for c in result.controls if c.control_id == "CVE-SLA-HIGH")
    assert high.status == "waived"
    assert "compensating control" in high.waiver_reasons
