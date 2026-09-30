"""Tests for the CVE Remediation SLA framework: per-severity windows aged from first detection."""

from datetime import datetime, timedelta, timezone

import pytest

from app.models.finding import FindingType, Severity
from app.services.compliance.frameworks.base import EvaluationInput
from app.services.compliance.frameworks.cve_remediation_sla import (
    CveRemediationSlaFramework,
    _is_overdue,
)
from tests.helpers.compliance import evaluation_input


def _vuln(severity: Severity, days_ago: int, **kwargs) -> dict:
    return {
        "_id": kwargs.pop("_id", f"f-{severity.value}-{days_ago}"),
        "type": FindingType.VULNERABILITY.value,
        "severity": severity.value,
        "first_seen_at": datetime.now(timezone.utc) - timedelta(days=days_ago),
        **kwargs,
    }


def _eval_input(findings: list) -> EvaluationInput:
    return evaluation_input(findings=findings)


class TestDefaultSlaBuckets:
    @pytest.mark.asyncio
    async def test_default_critical_window_is_7_days(self):
        framework = CveRemediationSlaFramework()
        result = await framework.evaluate(_eval_input([_vuln(Severity.CRITICAL, 8)]))
        critical_control = next(c for c in result.controls if c.severity == Severity.CRITICAL)
        assert critical_control.status == "failed"

    @pytest.mark.asyncio
    async def test_default_high_window_is_30_days(self):
        framework = CveRemediationSlaFramework()
        result = await framework.evaluate(_eval_input([_vuln(Severity.HIGH, 25)]))
        high = next(c for c in result.controls if c.severity == Severity.HIGH)
        assert high.status == "passed"


class TestEvaluationSemantics:
    @pytest.mark.asyncio
    async def test_empty_input_yields_three_passing_buckets(self):
        framework = CveRemediationSlaFramework()
        result = await framework.evaluate(_eval_input([]))
        assert result.summary["failed"] == 0
        assert result.summary["total"] == 3  # CRITICAL / HIGH / MEDIUM buckets

    @pytest.mark.asyncio
    async def test_waived_overdue_marks_control_waived_with_reason(self):
        framework = CveRemediationSlaFramework()
        result = await framework.evaluate(
            _eval_input([_vuln(Severity.HIGH, days_ago=60, waived=True, waiver_reason="compensating control")])
        )
        high = next(c for c in result.controls if c.severity == Severity.HIGH)
        assert high.status == "waived"
        assert "compensating control" in high.waiver_reasons

    @pytest.mark.asyncio
    async def test_waiver_reasons_name_only_the_waived_findings(self):
        framework = CveRemediationSlaFramework()
        result = await framework.evaluate(
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
        }

    def test_an_age_of_exactly_the_sla_window_is_overdue(self):
        assert _is_overdue(self._finding(self._NOW - timedelta(days=7)), Severity.CRITICAL, 7, self._NOW) is True

    def test_an_age_one_microsecond_short_of_the_window_is_not_overdue(self):
        first_seen = self._NOW - timedelta(days=7) + timedelta(microseconds=1)
        assert _is_overdue(self._finding(first_seen), Severity.CRITICAL, 7, self._NOW) is False

    def test_a_document_creation_date_is_not_a_first_detection(self):
        finding = self._finding(self._NOW - timedelta(days=200))
        finding["created_at"] = finding.pop("first_seen_at")
        assert _is_overdue(finding, Severity.CRITICAL, 7, self._NOW) is False
