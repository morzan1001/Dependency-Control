"""CVE Remediation SLA: one control per severity bucket; FAILED when overdue."""

from datetime import datetime, timedelta, timezone
from typing import Any

from app.models.finding import FindingType, Severity
from app.schemas.compliance import ControlResult, FrameworkEvaluation, ReportFramework
from app.services.compliance.frameworks.base import (
    EvaluationInput,
    _classify,
    _waiver_reasons,
    build_evaluation,
)
from app.services.recommendation.common import live_advisories

SLA_DAYS: dict[Severity, int] = {
    Severity.CRITICAL: 7,
    Severity.HIGH: 30,
    Severity.MEDIUM: 90,
}


def _control_title(severity: Severity, sla_days: int) -> str:
    label = severity.value.capitalize()
    return f"{label}-severity vulnerabilities remediated within {sla_days} days"


class CveRemediationSlaFramework:
    key: ReportFramework = ReportFramework.CVE_REMEDIATION_SLA
    name: str = "CVE Remediation SLA"
    version: str = "1"
    disclaimer: str | None = None

    async def evaluate(self, data: EvaluationInput) -> FrameworkEvaluation:
        now = datetime.now(timezone.utc)

        controls: list[ControlResult] = []
        for severity, sla_days in SLA_DAYS.items():
            title = _control_title(severity, sla_days)
            overdue = [f for f in data.findings if _is_overdue(f, severity, sla_days, now)]
            status, evidence, status_reason = _classify(overdue, data.coverage)
            controls.append(
                ControlResult(
                    control_id=f"CVE-SLA-{severity.value.upper()}",
                    title=title,
                    description=(
                        f"All {severity.value} vulnerabilities must be "
                        f"remediated (fixed or waived) within {sla_days} days."
                    ),
                    status=status,
                    severity=severity,
                    evidence_finding_ids=evidence,
                    evidence_asset_bom_refs=[],
                    waiver_reasons=_waiver_reasons(overdue),
                    remediation=(
                        "Upgrade affected components to their patched version, "
                        "or submit a waiver with documented compensating controls."
                    ),
                    status_reason=status_reason,
                )
            )

        return build_evaluation(self, data, controls, coverage=data.coverage)


def _is_overdue(
    finding: dict[str, Any],
    severity: Severity,
    sla_days: int,
    now: datetime,
) -> bool:
    if finding.get("type") != FindingType.VULNERABILITY.value:
        return False
    details = finding.get("details") or {}
    # A waived finding stays waived evidence under each of its advisories' severities.
    advisories = (details.get("vulnerabilities") or []) if finding.get("waived") else live_advisories(details)
    if not any(advisory.get("severity") == severity.value for advisory in advisories):
        return False
    # A copy stored before first detection was recorded carries only its scan's time.
    first_seen = finding.get("first_seen_at") or finding.get("scan_created_at")
    return first_seen is not None and now - first_seen >= timedelta(days=sla_days)
