"""Tests for the CVE Remediation SLA framework: default and configurable per-severity windows."""

from datetime import datetime, timedelta, timezone

import pytest

from app.models.finding import FindingType, Severity
from app.services.compliance.frameworks.base import EvaluationInput
from app.services.compliance.frameworks.cve_remediation_sla import (
    CveRemediationSlaFramework,
    _is_overdue,
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
        framework = CveRemediationSlaFramework()
        result = await framework.evaluate_async(_eval_input([_vuln(Severity.CRITICAL, 8)]))
        critical_control = next(c for c in result.controls if c.severity == Severity.CRITICAL)
        assert critical_control.status == "failed"

    @pytest.mark.asyncio
    async def test_default_high_window_is_30_days(self):
        framework = CveRemediationSlaFramework()
        result = await framework.evaluate_async(_eval_input([_vuln(Severity.HIGH, 25)]))
        high = next(c for c in result.controls if c.severity == Severity.HIGH)
        assert high.status == "passed"


class TestConfigurableSlaBuckets:
    @pytest.mark.asyncio
    async def test_custom_windows_override_defaults(self):
        framework = CveRemediationSlaFramework(
            sla_days_by_severity={
                Severity.CRITICAL: 3,
                Severity.HIGH: 14,
                Severity.MEDIUM: 30,
            }
        )
        # 4 days is inside the 7-day default but past the 3-day override.
        result = await framework.evaluate_async(_eval_input([_vuln(Severity.CRITICAL, 4)]))
        critical = next(c for c in result.controls if c.severity == Severity.CRITICAL)
        assert critical.status == "failed"

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
        framework = CveRemediationSlaFramework(sla_days_by_severity={Severity.CRITICAL: 3})
        result = await framework.evaluate_async(
            _eval_input([_vuln(Severity.HIGH, 25)])  # under default 30-day window
        )
        high = next(c for c in result.controls if c.severity == Severity.HIGH)
        assert high.status == "passed"

    @pytest.mark.asyncio
    async def test_overrides_must_be_positive(self):
        # A zero/negative window would make every finding immediately overdue.
        with pytest.raises(ValueError):
            CveRemediationSlaFramework(sla_days_by_severity={Severity.CRITICAL: 0})


class TestEvaluationSemantics:
    def test_sync_evaluate_rejected(self):
        framework = CveRemediationSlaFramework()
        with pytest.raises(RuntimeError, match="async-only"):
            framework.evaluate(_eval_input([]))

    @pytest.mark.asyncio
    async def test_empty_input_yields_three_passing_buckets(self):
        framework = CveRemediationSlaFramework()
        result = await framework.evaluate_async(_eval_input([]))
        assert result.summary["failed"] == 0
        assert result.summary["total"] == 3  # CRITICAL / HIGH / MEDIUM buckets

    @pytest.mark.asyncio
    async def test_fixed_findings_excluded_from_sla(self):
        framework = CveRemediationSlaFramework()
        result = await framework.evaluate_async(_eval_input([_vuln(Severity.CRITICAL, days_ago=30, status="fixed")]))
        critical = next(c for c in result.controls if c.severity == Severity.CRITICAL)
        assert critical.status == "passed"

    @pytest.mark.asyncio
    async def test_waived_overdue_marks_control_waived_with_reason(self):
        framework = CveRemediationSlaFramework()
        result = await framework.evaluate_async(
            _eval_input([_vuln(Severity.HIGH, days_ago=60, waived=True, waiver_reason="compensating control")])
        )
        high = next(c for c in result.controls if c.severity == Severity.HIGH)
        assert high.status == "waived"
        assert "compensating control" in high.waiver_reasons

    @pytest.mark.asyncio
    async def test_waiver_reasons_name_only_the_waived_findings(self):
        framework = CveRemediationSlaFramework()
        result = await framework.evaluate_async(
            _eval_input(
                [
                    _vuln(
                        Severity.HIGH,
                        days_ago=60,
                        _id="f-waived",
                        waived=True,
                        waiver_reason="compensating control",
                    ),
                    _vuln(Severity.HIGH, days_ago=61, _id="f-open"),
                ]
            )
        )
        high = next(c for c in result.controls if c.severity == Severity.HIGH)
        assert high.status == "failed"
        assert high.waiver_reasons == ["compensating control"]


class TestOverdueBoundary:
    _NOW = datetime(2026, 4, 20, 12, 0, tzinfo=timezone.utc)

    def _finding(self, first_seen: datetime) -> dict:
        return {
            "_id": "f-boundary",
            "type": FindingType.VULNERABILITY.value,
            "severity": Severity.CRITICAL.value,
            "first_seen_at": first_seen,
            "status": "open",
        }

    def test_an_age_of_exactly_the_sla_window_is_overdue(self):
        assert _is_overdue(self._finding(self._NOW - timedelta(days=7)), Severity.CRITICAL, 7, self._NOW) is True

    def test_an_age_one_microsecond_short_of_the_window_is_not_overdue(self):
        first_seen = self._NOW - timedelta(days=7) + timedelta(microseconds=1)
        assert _is_overdue(self._finding(first_seen), Severity.CRITICAL, 7, self._NOW) is False

    def test_a_naive_first_seen_at_is_read_as_utc(self):
        """Motor is built without tz_aware, so Mongo hands the framework naive UTC datetimes."""
        naive = (self._NOW - timedelta(days=30)).replace(tzinfo=None)
        assert _is_overdue(self._finding(naive), Severity.CRITICAL, 7, self._NOW) is True

    @pytest.mark.asyncio
    async def test_a_naive_timestamp_inside_the_window_keeps_the_control_passing(self):
        framework = CveRemediationSlaFramework()
        naive = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=2)
        result = await framework.evaluate_async(_eval_input([_vuln(Severity.CRITICAL, 2, first_seen_at=naive)]))
        critical = next(c for c in result.controls if c.severity == Severity.CRITICAL)
        assert critical.status == "passed"

    @pytest.mark.asyncio
    async def test_a_naive_timestamp_past_the_window_fails_the_control(self):
        framework = CveRemediationSlaFramework()
        naive = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=60)
        result = await framework.evaluate_async(_eval_input([_vuln(Severity.HIGH, 60, first_seen_at=naive)]))
        high = next(c for c in result.controls if c.severity == Severity.HIGH)
        assert high.status == "failed"
