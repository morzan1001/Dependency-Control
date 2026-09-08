from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.schemas.compliance import EvaluationCoverage, InputCoverage, ReportFramework
from app.schemas.pqc_migration import (
    MigrationItem,
    MigrationItemStatus,
    MigrationPlanResponse,
    MigrationPlanSummary,
)
from app.services.analytics.scopes import ResolvedScope
from app.services.compliance.frameworks.base import EvaluationInput
from app.services.compliance.frameworks.pqc_migration_plan import (
    PQCMigrationPlanFramework,
)

_COMPLETE_INPUT = InputCoverage(evaluated=0, in_scope=0, limit=1)
_PLAN_ITEMS_BUILT = 2
_ITEMS_IN_SCOPE = 4200


def _input(db=None, coverage=None):
    return EvaluationInput(
        resolved=ResolvedScope(scope="user", scope_id=None, project_ids=["p"]),
        scope_description="user",
        crypto_assets=[],
        findings=[],
        policy_rules=[],
        policy_version=1,
        iana_catalog_version=1,
        scan_ids=["s1"],
        db=db,
        coverage=coverage,
    )


def _plan(total_items=_PLAN_ITEMS_BUILT, items_returned=_PLAN_ITEMS_BUILT):
    return MigrationPlanResponse(
        scope="user",
        scope_id=None,
        generated_at=datetime.now(timezone.utc),
        items=[
            MigrationItem(
                asset_bom_ref="r1",
                asset_name="RSA",
                project_ids=["p"],
                asset_count=1,
                source_family="RSA",
                source_primitive="pke",
                use_case="key-exchange",
                recommended_pqc="ML-KEM-768",
                recommended_standard="FIPS 203",
                notes="...",
                priority_score=95,
                status=MigrationItemStatus.MIGRATE_NOW,
            ),
            MigrationItem(
                asset_bom_ref="r2",
                asset_name="ECDSA",
                project_ids=["p"],
                asset_count=1,
                source_family="ECDSA",
                source_primitive="signature",
                use_case="digital-signature",
                recommended_pqc="ML-DSA-65",
                recommended_standard="FIPS 204",
                notes="...",
                priority_score=15,
                status=MigrationItemStatus.MONITOR,
            ),
        ],
        summary=MigrationPlanSummary(
            total_items=total_items,
            items_returned=items_returned,
            status_counts={"migrate_now": 1, "monitor": 1},
            earliest_deadline=None,
        ),
        mappings_version=1,
    )


def _engine_coverage():
    return EvaluationCoverage(findings=_COMPLETE_INPUT, crypto_assets=_COMPLETE_INPUT)


async def _evaluate(plan, coverage=None):
    with patch(
        "app.services.compliance.frameworks.pqc_migration_plan.PQCMigrationPlanGenerator",
    ) as gen_cls:
        gen_cls.return_value = MagicMock(generate=AsyncMock(return_value=plan))
        return await PQCMigrationPlanFramework().evaluate_async(_input(db=MagicMock(), coverage=coverage))


@pytest.mark.asyncio
async def test_a_control_list_cut_at_the_plan_ceiling_says_what_it_left_out():
    """One control per plan item, so past the ceiling the control list and the plan summary
    disagree with nothing to say which is right."""
    plan = _plan(total_items=_ITEMS_IN_SCOPE, items_returned=_PLAN_ITEMS_BUILT)

    result = await _evaluate(plan, coverage=_engine_coverage())

    assert result.coverage is not None
    assert result.coverage.plan_items is not None
    assert result.coverage.plan_items.in_scope == _ITEMS_IN_SCOPE
    assert result.coverage.plan_items.evaluated == _PLAN_ITEMS_BUILT
    assert result.coverage.complete is False


@pytest.mark.asyncio
async def test_a_complete_plan_reports_complete_coverage():
    result = await _evaluate(_plan(), coverage=_engine_coverage())

    assert result.coverage is not None
    assert result.coverage.complete is True


def test_framework_identity():
    fw = PQCMigrationPlanFramework()
    assert fw.key == ReportFramework.PQC_MIGRATION_PLAN
    assert fw.name == "PQC Migration Plan"


@pytest.mark.asyncio
async def test_evaluate_async_turns_plan_items_into_controls():
    fw = PQCMigrationPlanFramework()
    db = MagicMock()
    plan = _plan()
    with patch(
        "app.services.compliance.frameworks.pqc_migration_plan.PQCMigrationPlanGenerator",
    ) as gen_cls:
        gen_instance = MagicMock(generate=AsyncMock(return_value=plan))
        gen_cls.return_value = gen_instance
        result = await fw.evaluate_async(_input(db=db))

    assert len(result.controls) == 2
    statuses = {c.control_id: (c.status if isinstance(c.status, str) else c.status.value) for c in result.controls}
    assert any(v == "failed" for v in statuses.values())
    assert any(v == "not_applicable" for v in statuses.values())


@pytest.mark.asyncio
async def test_scope_description_echoes_input():
    fw = PQCMigrationPlanFramework()
    db = MagicMock()
    plan = _plan()
    with patch(
        "app.services.compliance.frameworks.pqc_migration_plan.PQCMigrationPlanGenerator",
    ) as gen_cls:
        gen_cls.return_value = MagicMock(generate=AsyncMock(return_value=plan))
        inp = _input(db=db)
        inp.scope_description = "project 'payments'"
        result = await fw.evaluate_async(inp)
    assert result.scope_description == "project 'payments'"


def test_sync_evaluate_raises_runtime_error():
    """Sync entry point must fail loudly rather than call asyncio.run inside the FastAPI event loop."""
    fw = PQCMigrationPlanFramework()
    db = MagicMock()
    with pytest.raises(RuntimeError, match="evaluate_async"):
        fw.evaluate(_input(db=db))
