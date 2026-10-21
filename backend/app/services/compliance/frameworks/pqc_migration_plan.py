from app.models.finding import Severity
from app.schemas.compliance import ControlResult, ControlStatus, FrameworkEvaluation
from app.models.compliance_report import EvaluationCoverage, InputCoverage, ReportFramework
from app.schemas.pqc_migration import MigrationItem, MigrationItemStatus, MigrationPlanResponse
from app.services.compliance.frameworks.base import NAMES_SHOWN, EvaluationInput, build_evaluation
from app.services.pqc_migration.generator import PQCMigrationPlanGenerator
from app.services.recommendation.common import name_some

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

        return build_evaluation(
            self,
            data,
            [_item_to_control(item, plan.project_names) for item in plan.items],
            coverage=_coverage(data, plan),
            extra_inputs=(f"mappings={plan.mappings_version}",),
        )


def _coverage(data: EvaluationInput, plan: MigrationPlanResponse) -> EvaluationCoverage:
    """Past the plan's ceiling the control list is a cut of a plan whose summary counts every item."""
    return data.coverage.model_copy(
        update={
            "plan_items": InputCoverage(
                evaluated=plan.summary.items_returned,
                in_scope=plan.summary.total_items,
                limit=_PLAN_ITEM_LIMIT,
            )
        }
    )


def _item_to_control(item: MigrationItem, project_names: dict[str, str]) -> ControlResult:
    projects = name_some([project_names.get(p, p) for p in item.project_ids], NAMES_SHOWN)
    return ControlResult(
        control_id=f"PQC-{item.source_family}-{item.asset_bom_ref}",
        title=f"{item.source_family} -> {item.recommended_pqc}",
        description=(
            f"{item.source_family} ({item.source_primitive}) asset "
            f"'{item.asset_name}' should migrate to "
            f"{item.recommended_pqc} ({item.recommended_standard}). "
            f"{item.asset_count} occurrence(s) in {projects}. "
            f"Priority score: {item.priority_score}. {item.notes}"
        ),
        status=_STATUS_MAP[item.status],
        severity=_SEVERITY_MAP[item.status],
        evidence_finding_ids=[],
        evidence_asset_bom_refs=[item.asset_bom_ref],
        waiver_reasons=[],
        remediation=(f"Replace {item.source_family} with {item.recommended_pqc} per {item.recommended_standard}."),
    )
