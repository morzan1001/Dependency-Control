"""PQC Migration Plan framework: one ControlResult per plan item."""

from datetime import datetime, timezone

from app.models.finding import Severity
from app.schemas.compliance import (
    ControlResult,
    ControlStatus,
    EvaluationCoverage,
    FrameworkEvaluation,
    InputCoverage,
    ReportFramework,
)
from app.schemas.pqc_migration import MigrationItem, MigrationItemStatus, MigrationPlanResponse
from app.services.compliance.frameworks.base import (
    EvaluationInput,
    build_residual_risks,
    build_summary,
)
from app.services.pqc_migration.generator import PQCMigrationPlanGenerator

# One control per migratable group, so the plan's own ceiling is this report's control ceiling.
_PLAN_ITEM_LIMIT = 1000

_STATUS_MAP: dict[MigrationItemStatus, ControlStatus] = {
    MigrationItemStatus.MIGRATE_NOW: ControlStatus.FAILED,
    MigrationItemStatus.MIGRATE_SOON: ControlStatus.FAILED,
    MigrationItemStatus.PLAN_MIGRATION: ControlStatus.NOT_APPLICABLE,
    MigrationItemStatus.MONITOR: ControlStatus.NOT_APPLICABLE,
}

_SEVERITY_MAP: dict[MigrationItemStatus, Severity] = {
    MigrationItemStatus.MIGRATE_NOW: Severity.HIGH,
    MigrationItemStatus.MIGRATE_SOON: Severity.MEDIUM,
    MigrationItemStatus.PLAN_MIGRATION: Severity.LOW,
    MigrationItemStatus.MONITOR: Severity.INFO,
}


class PQCMigrationPlanFramework:
    key: ReportFramework = ReportFramework.PQC_MIGRATION_PLAN
    name: str = "PQC Migration Plan"
    version: str = "1"
    disclaimer: str | None = (
        "This report enumerates currently-detected quantum-vulnerable crypto "
        "assets and their NIST-standardised PQC successors. It is not a "
        "formal compliance assessment against an external standard."
    )

    async def evaluate(self, data: EvaluationInput) -> FrameworkEvaluation:
        plan = await PQCMigrationPlanGenerator(data.db).generate(
            resolved=data.resolved,
            limit=_PLAN_ITEM_LIMIT,
        )

        controls = [_item_to_control(item) for item in plan.items]
        return FrameworkEvaluation(
            framework_key=self.key,
            framework_name=self.name,
            framework_version=self.version,
            generated_at=datetime.now(timezone.utc),
            scope_description=data.scope_description,
            controls=controls,
            summary=build_summary(controls),
            residual_risks=build_residual_risks(controls),
            inputs_fingerprint=_fingerprint(plan),
            coverage=_coverage(data, plan),
        )


def _coverage(data: EvaluationInput, plan: MigrationPlanResponse) -> EvaluationCoverage:
    """The engine's coverage widened by the plan's own bound: past the ceiling the control list
    is a cut of a plan whose summary counts every item."""
    return data.coverage.model_copy(
        update={
            "plan_items": InputCoverage(
                evaluated=plan.summary.items_returned,
                in_scope=plan.summary.total_items,
                limit=_PLAN_ITEM_LIMIT,
            )
        }
    )


def _item_to_control(item: MigrationItem) -> ControlResult:
    return ControlResult(
        control_id=f"PQC-{item.source_family}-{item.asset_bom_ref}",
        title=f"{item.source_family} -> {item.recommended_pqc}",
        description=(
            f"{item.source_family} ({item.source_primitive}) asset "
            f"'{item.asset_name}' should migrate to "
            f"{item.recommended_pqc} ({item.recommended_standard}). "
            f"Priority score: {item.priority_score}. {item.notes}"
        ),
        status=_STATUS_MAP[item.status],
        severity=_SEVERITY_MAP[item.status],
        evidence_finding_ids=[],
        evidence_asset_bom_refs=[item.asset_bom_ref],
        waiver_reasons=[],
        remediation=(f"Replace {item.source_family} with {item.recommended_pqc} per {item.recommended_standard}."),
    )


def _fingerprint(plan: MigrationPlanResponse) -> str:
    return f"pqc-mappings-v{plan.mappings_version}"
