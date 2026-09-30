from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.schemas.compliance import EvaluationCoverage, ReportFramework
from app.schemas.pqc_migration import (
    MigrationItem,
    MigrationItemStatus,
    MigrationPlanResponse,
    MigrationPlanSummary,
)
from app.services.compliance.frameworks.pqc_migration_plan import (
    PQCMigrationPlanFramework,
)
from tests.helpers.compliance import evaluation_input

_PLAN_ITEMS_BUILT = 2
_ITEMS_IN_SCOPE = 4200


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


async def _evaluate(plan, **fields):
    with patch(
        "app.services.compliance.frameworks.pqc_migration_plan.PQCMigrationPlanGenerator",
    ) as gen_cls:
        gen_cls.return_value = MagicMock(generate=AsyncMock(return_value=plan))
        return await PQCMigrationPlanFramework().evaluate(evaluation_input(**fields))


@pytest.mark.asyncio
async def test_a_control_list_cut_at_the_plan_ceiling_says_what_it_left_out():
    """One control per plan item, so past the ceiling the control list and the plan summary
    disagree with nothing to say which is right."""
    plan = _plan(total_items=_ITEMS_IN_SCOPE, items_returned=_PLAN_ITEMS_BUILT)

    result = await _evaluate(plan)

    assert result.coverage.plan_items is not None
    assert result.coverage.plan_items.in_scope == _ITEMS_IN_SCOPE
    assert result.coverage.plan_items.evaluated == _PLAN_ITEMS_BUILT
    assert result.coverage.complete is False


@pytest.mark.asyncio
async def test_a_complete_plan_reports_complete_coverage():
    result = await _evaluate(_plan())

    assert result.coverage.complete is True


@pytest.mark.asyncio
async def test_a_plan_keeps_the_scope_gaps_the_engine_found():
    gap = "project 'payments' has no usable scan"

    result = await _evaluate(_plan(), coverage=EvaluationCoverage(gaps=[gap]))

    assert result.coverage.gaps == [gap]
    assert result.coverage.complete is False


def test_framework_identity():
    fw = PQCMigrationPlanFramework()
    assert fw.key == ReportFramework.PQC_MIGRATION_PLAN
    assert fw.name == "PQC Migration Plan"


@pytest.mark.asyncio
async def test_evaluate_turns_plan_items_into_controls():
    result = await _evaluate(_plan())

    assert len(result.controls) == 2
    statuses = {c.control_id: (c.status if isinstance(c.status, str) else c.status.value) for c in result.controls}
    assert any(v == "failed" for v in statuses.values())
    assert any(v == "not_applicable" for v in statuses.values())


@pytest.mark.asyncio
async def test_scope_description_echoes_input():
    result = await _evaluate(_plan(), scope_description="project 'payments'")

    assert result.scope_description == "project 'payments'"
