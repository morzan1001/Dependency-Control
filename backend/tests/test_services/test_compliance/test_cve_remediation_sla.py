"""Tests for the CVE Remediation SLA framework — focus on the
configurable-windows behaviour added in P5.4.

The framework was previously hard-coded to 7 / 30 / 90 days for
CRITICAL / HIGH / MEDIUM. The disclaimer on the class admitted this
was provisional ("Customise via project policy in a future iteration").
This is that future iteration: callers can pass an override dict and
the controls' titles, descriptions, and overdue calculations follow it.
"""

from datetime import datetime, timedelta, timezone

import pytest

from app.models.finding import FindingType, Severity
from app.services.compliance.frameworks.base import EvaluationInput
from app.services.compliance.frameworks.cve_remediation_sla import (
    CveRemediationSlaFramework,
)


def _vuln(severity: Severity, days_ago: int, status: str = "open", **kwargs) -> dict:
    return {
        "_id": kwargs.pop("_id", f"f-{severity.value}-{days_ago}"),
        "type": FindingType.VULNERABILITY.value,
        "severity": severity.value,
        "first_seen_at": datetime.now(timezone.utc) - timedelta(days=days_ago),
        "status": status,
        **kwargs,
    }


def _eval_input(findings: list) -> EvaluationInput:
    return EvaluationInput(
        findings=findings,
        crypto_assets=[],
        scope_description="test",
        resolved=[],
        policy_rules=[],
        policy_version="0",
        iana_catalog_version="0",
        scan_ids=[],
    )


class TestDefaultSlaBuckets:
    @pytest.mark.asyncio
    async def test_default_critical_window_is_7_days(self):
        # 8 days old, still open -> overdue under default 7-day window.
        framework = CveRemediationSlaFramework()
        result = await framework.evaluate_async(_eval_input([_vuln(Severity.CRITICAL, 8)]))
        critical_control = next(c for c in result.controls if c.severity == Severity.CRITICAL)
        assert critical_control.status =="failed"

    @pytest.mark.asyncio
    async def test_default_high_window_is_30_days(self):
        framework = CveRemediationSlaFramework()
        # 25 days old HIGH should still pass under default 30-day window.
        result = await framework.evaluate_async(_eval_input([_vuln(Severity.HIGH, 25)]))
        high = next(c for c in result.controls if c.severity == Severity.HIGH)
        assert high.status == "passed"


class TestConfigurableSlaBuckets:
    @pytest.mark.asyncio
    async def test_custom_windows_override_defaults(self):
        # A stricter org wants 3 / 14 / 30 instead of 7 / 30 / 90.
        framework = CveRemediationSlaFramework(
            sla_days_by_severity={
                Severity.CRITICAL: 3,
                Severity.HIGH: 14,
                Severity.MEDIUM: 30,
            }
        )
        # 4-day-old CRITICAL is overdue (would still be inside the 7-day default).
        result = await framework.evaluate_async(_eval_input([_vuln(Severity.CRITICAL, 4)]))
        critical = next(c for c in result.controls if c.severity == Severity.CRITICAL)
        assert critical.status =="failed"

    @pytest.mark.asyncio
    async def test_custom_windows_appear_in_control_titles(self):
        framework = CveRemediationSlaFramework(
            sla_days_by_severity={
                Severity.CRITICAL: 3,
                Severity.HIGH: 14,
                Severity.MEDIUM: 30,
            }
        )
        result = await framework.evaluate_async(_eval_input([]))
        titles = [c.title for c in result.controls]
        assert any("3 days" in t for t in titles)
        assert any("14 days" in t for t in titles)
        assert any("30 days" in t for t in titles)

    @pytest.mark.asyncio
    async def test_partial_override_falls_back_to_defaults(self):
        # Caller only overrides CRITICAL — HIGH/MEDIUM should keep their defaults.
        framework = CveRemediationSlaFramework(
            sla_days_by_severity={Severity.CRITICAL: 3}
        )
        result = await framework.evaluate_async(
            _eval_input([_vuln(Severity.HIGH, 25)])  # under default 30
        )
        high = next(c for c in result.controls if c.severity == Severity.HIGH)
        assert high.status == "passed"

    @pytest.mark.asyncio
    async def test_overrides_must_be_positive(self):
        # Defensive: a zero/negative window would mean every finding is
        # immediately overdue, which is almost certainly a misconfiguration.
        with pytest.raises(ValueError):
            CveRemediationSlaFramework(
                sla_days_by_severity={Severity.CRITICAL: 0}
            )
