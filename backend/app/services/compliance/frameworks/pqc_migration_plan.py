"""
PQC Migration Plan as a compliance "framework".

Delegates control-list generation to PQCMigrationPlanGenerator. Each plan
item becomes one ControlResult:
  - migrate_now    -> failed (HIGH severity)
  - migrate_soon   -> failed (MEDIUM severity)
  - plan_migration -> not_applicable (informational)
  - monitor        -> not_applicable

This framework is async-only because the underlying generator issues DB
queries. The sync `evaluate(...)` entry point raises RuntimeError — callers
must dispatch on `hasattr(framework, "evaluate_async")` and await it.
"""

from datetime import datetime, timezone
from typing import Dict, List

from app.models.finding import Severity
from app.schemas.compliance import (
    ControlDefinition, ControlResult, ControlStatus,
    FrameworkEvaluation, ReportFramework, ResidualRisk,
)
from app.schemas.pqc_migration import MigrationItem, MigrationPlanResponse
from app.services.compliance.frameworks.base import EvaluationInput
from app.services.pqc_migration.generator import PQCMigrationPlanGenerator


_STATUS_MAP: Dict[str, ControlStatus] = {
    "migrate_now": ControlStatus.FAILED,
    "migrate_soon": ControlStatus.FAILED,
    "plan_migration": ControlStatus.NOT_APPLICABLE,
    "monitor": ControlStatus.NOT_APPLICABLE,
}

_SEVERITY_MAP: Dict[str, Severity] = {
    "migrate_now": Severity.HIGH,
    "migrate_soon": Severity.MEDIUM,
    "plan_migration": Severity.LOW,
    "monitor": Severity.INFO,
}


class PQCMigrationPlanFramework:
    key = ReportFramework.PQC_MIGRATION_PLAN
    name = "PQC Migration Plan"
    version = "1"
    source_url = "https://csrc.nist.gov/Projects/post-quantum-cryptography"
    disclaimer = (
        "This report enumerates currently-detected quantum-vulnerable crypto "
        "assets and their NIST-standardised PQC successors. It is not a "
        "formal compliance assessment against an external standard."
    )
    controls: List[ControlDefinition] = []

    def evaluate(self, data: EvaluationInput) -> FrameworkEvaluation:
        """Sync entry point is not supported — see module docstring.

        Callers must dispatch on ``hasattr(framework, "evaluate_async")`` and
        await the async variant. Keeping a loud error here protects against
        accidental sync use from a running event loop, where the previous
        ``asyncio.run(...)`` implementation would crash with RuntimeError.
        """
        raise RuntimeError("Use evaluate_async for PQC framework")

    async def evaluate_async(self, data: EvaluationInput) -> FrameworkEvaluation:
        if data.db is None:
            raise ValueError("EvaluationInput.db is required for PQC meta-framework")

        plan = await PQCMigrationPlanGenerator(data.db).generate(
            resolved=data.resolved, limit=1000,
        )

        controls = [_item_to_control(item) for item in plan.items]
        return FrameworkEvaluation(
            framework_key=self.key,
            framework_name=self.name,
            framework_version=self.version,
            generated_at=datetime.now(timezone.utc),
            scope_description=data.scope_description,
            controls=controls,
            summary=_summary(controls),
            residual_risks=_residual_risks(controls),
            inputs_fingerprint=_fingerprint(plan),
        )


def _item_to_control(item: MigrationItem) -> ControlResult:
    bucket = _bucket(item.status)
    status = _STATUS_MAP.get(bucket, ControlStatus.NOT_APPLICABLE)
    sev = _SEVERITY_MAP.get(bucket, Severity.INFO)
    return ControlResult(
        control_id=f"PQC-{item.source_family}-{item.asset_bom_ref}",
        title=f"{item.source_family} -> {item.recommended_pqc}",
        description=(
            f"{item.source_family} ({item.source_primitive}) asset "
            f"'{item.asset_name}' should migrate to "
            f"{item.recommended_pqc} ({item.recommended_standard}). "
            f"Priority score: {item.priority_score}. {item.notes}"
        ),
        status=status,
        severity=sev,
        evidence_finding_ids=[],
        evidence_asset_bom_refs=[item.asset_bom_ref],
        waiver_reasons=[],
        remediation=(
            f"Replace {item.source_family} with {item.recommended_pqc} "
            f"per {item.recommended_standard}."
        ),
    )


def _bucket(status) -> str:
    return status if isinstance(status, str) else status.value


def _status_value(status) -> str:
    return status if isinstance(status, str) else status.value


def _summary(controls: List[ControlResult]) -> Dict[str, int]:
    counts = {
        "passed": 0, "failed": 0, "waived": 0, "not_applicable": 0,
        "total": len(controls),
    }
    for c in controls:
        key = _status_value(c.status)
        counts[key] = counts.get(key, 0) + 1
    return counts


def _residual_risks(controls: List[ControlResult]) -> List[ResidualRisk]:
    return [
        ResidualRisk(
            control_id=c.control_id, title=c.title,
            severity=c.severity, description=c.description,
        )
        for c in controls
        if _status_value(c.status) == "failed"
    ]


def _fingerprint(plan: MigrationPlanResponse) -> str:
    return f"pqc-mappings-v{plan.mappings_version}"
