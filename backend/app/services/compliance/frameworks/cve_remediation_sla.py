"""CVE Remediation SLA: one control per severity bucket; FAILED when overdue."""

import asyncio
from datetime import datetime, timedelta, timezone
from typing import Any, ClassVar

from app.core import ensure_utc
from app.models.finding import FindingType, Severity
from app.schemas.compliance import (
    ControlDefinition,
    ControlResult,
    FrameworkEvaluation,
    ReportFramework,
)
from app.services.compliance.frameworks.base import (
    EvaluationInput,
    _classify,
    _waiver_reason,
    build_residual_risks,
    build_summary,
)

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
    source_url: str = "https://www.first.org/cvss/"
    disclaimer: str | None = None
    controls: ClassVar[list[ControlDefinition]] = []

    def evaluate(self, data: EvaluationInput) -> FrameworkEvaluation:
        raise RuntimeError("CveRemediationSlaFramework is async-only; callers must dispatch via evaluate_async()")

    async def evaluate_async(self, data: EvaluationInput) -> FrameworkEvaluation:
        # yield once so sibling framework tasks can progress
        await asyncio.sleep(0)
        findings = data.findings or []
        now = datetime.now(timezone.utc)

        controls: list[ControlResult] = []
        for severity, sla_days in SLA_DAYS.items():
            title = _control_title(severity, sla_days)
            overdue = [f for f in findings if _is_overdue(f, severity, sla_days, now)]
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
                    waiver_reasons=[_waiver_reason(f) for f in overdue if f.get("waived")],
                    remediation=(
                        "Upgrade affected components to their patched version, "
                        "or submit a waiver with documented compensating controls."
                    ),
                    status_reason=status_reason,
                )
            )

        return FrameworkEvaluation(
            framework_key=self.key,
            framework_name=self.name,
            framework_version=self.version,
            generated_at=now,
            scope_description=data.scope_description,
            controls=controls,
            summary=build_summary(controls),
            residual_risks=build_residual_risks(controls),
            inputs_fingerprint="cve-remediation-sla-v1",
        )


def _is_overdue(
    finding: dict[str, Any],
    severity: Severity,
    sla_days: int,
    now: datetime,
) -> bool:
    if finding.get("type") != FindingType.VULNERABILITY.value:
        return False
    fsev = finding.get("severity")
    if fsev != severity.value and fsev != severity:
        return False
    first_seen = ensure_utc(finding.get("first_seen_at"))
    return first_seen is not None and now - first_seen >= timedelta(days=sla_days)
