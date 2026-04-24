"""
CVE Remediation SLA — SBOM-side compliance "framework".

Checks that open vulnerabilities are remediated within their severity
SLA window. Default windows (configurable via env in future):
  - CRITICAL: 7 days
  - HIGH: 30 days
  - MEDIUM: 90 days

Each severity bucket becomes one control. Findings older than the SLA
window whose status is not ``fixed`` / ``waived`` trigger FAILED.

Async-only — pulls findings from EvaluationInput (already loaded by
engine). Callers dispatch via ``evaluate_async``.
"""

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from app.models.finding import FindingType, Severity
from app.schemas.compliance import (
    ControlDefinition,
    ControlResult,
    ControlStatus,
    FrameworkEvaluation,
    ReportFramework,
    ResidualRisk,
)
from app.services.compliance.frameworks.base import EvaluationInput


# Severity -> (sla_days, control_title, severity_label)
_SLA_BUCKETS: List[Tuple[Severity, int, str]] = [
    (Severity.CRITICAL, 7, "Critical vulnerabilities remediated within 7 days"),
    (Severity.HIGH, 30, "High-severity vulnerabilities remediated within 30 days"),
    (Severity.MEDIUM, 90, "Medium-severity vulnerabilities remediated within 90 days"),
]


class CveRemediationSlaFramework:
    key: ReportFramework = ReportFramework.CVE_REMEDIATION_SLA
    name: str = "CVE Remediation SLA"
    version: str = "1"
    source_url: str = "https://www.first.org/cvss/"
    disclaimer: Optional[str] = (
        "SLA windows are platform defaults (7 / 30 / 90 days for "
        "CRITICAL / HIGH / MEDIUM). Customise via project policy in a "
        "future iteration."
    )
    controls: List[ControlDefinition] = []

    def evaluate(self, data: EvaluationInput) -> FrameworkEvaluation:
        raise RuntimeError(
            "CveRemediationSlaFramework is async-only; callers must dispatch via evaluate_async()"
        )

    async def evaluate_async(self, data: EvaluationInput) -> FrameworkEvaluation:
        findings = data.findings or []
        now = datetime.now(timezone.utc)

        controls: List[ControlResult] = []
        for severity, sla_days, title in _SLA_BUCKETS:
            overdue = [
                f for f in findings if _is_overdue(f, severity, sla_days, now)
            ]
            status, evidence = _classify(overdue)
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
                )
            )

        summary = _build_summary(controls)
        residuals = [
            ResidualRisk(
                control_id=c.control_id,
                title=c.title,
                severity=c.severity,
                description=c.description,
            )
            for c in controls
            if (c.status if isinstance(c.status, str) else c.status.value) == "failed"
        ]
        return FrameworkEvaluation(
            framework_key=self.key,
            framework_name=self.name,
            framework_version=self.version,
            generated_at=now,
            scope_description=data.scope_description,
            controls=controls,
            summary=summary,
            residual_risks=residuals,
            inputs_fingerprint="cve-remediation-sla-v1",
        )


def _is_overdue(
    finding: Dict[str, Any],
    severity: Severity,
    sla_days: int,
    now: datetime,
) -> bool:
    if finding.get("type") != FindingType.VULNERABILITY.value:
        return False
    fsev = finding.get("severity")
    if fsev != severity.value and fsev != severity:
        return False
    first_seen = finding.get("first_seen_at") or finding.get("created_at")
    if first_seen is None:
        return False
    if isinstance(first_seen, str):
        try:
            first_seen = datetime.fromisoformat(first_seen.replace("Z", "+00:00"))
        except ValueError:
            return False
    if not isinstance(first_seen, datetime):
        return False
    if first_seen.tzinfo is None:
        first_seen = first_seen.replace(tzinfo=timezone.utc)
    age = now - first_seen
    if age < timedelta(days=sla_days):
        return False
    # Not yet fixed — finding still open
    if finding.get("status") == "fixed":
        return False
    return True


def _classify(overdue: List[Dict[str, Any]]) -> tuple[ControlStatus, List[str]]:
    if not overdue:
        return ControlStatus.PASSED, []
    active = [f for f in overdue if not f.get("waived")]
    evidence_ids = [str(f.get("_id") or f.get("id") or "") for f in overdue if f.get("_id") or f.get("id")]
    if active:
        return ControlStatus.FAILED, evidence_ids
    return ControlStatus.WAIVED, evidence_ids


def _waiver_reason(f: Dict[str, Any]) -> str:
    return str(f.get("waiver_reason") or "")


def _build_summary(controls: List[ControlResult]) -> Dict[str, int]:
    counts = {"passed": 0, "failed": 0, "waived": 0, "not_applicable": 0, "total": len(controls)}
    for c in controls:
        key = c.status if isinstance(c.status, str) else c.status.value
        counts[key] = counts.get(key, 0) + 1
    return counts
