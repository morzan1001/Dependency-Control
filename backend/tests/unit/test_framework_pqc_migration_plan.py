from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.schemas.compliance import ReportFramework
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


def _input(db=None):
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
    )


def _plan():
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
            total_items=2,
            status_counts={"migrate_now": 1, "monitor": 1},
            earliest_deadline=None,
        ),
        mappings_version=1,
    )


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
    """Sync entry point must fail loudly — it used to call asyncio.run(...)
    inside the FastAPI BackgroundTask event loop and crash in production."""
    fw = PQCMigrationPlanFramework()
    db = MagicMock()
    with pytest.raises(RuntimeError, match="evaluate_async"):
        fw.evaluate(_input(db=db))
