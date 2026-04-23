from unittest.mock import AsyncMock, MagicMock, patch

import pytest


@pytest.mark.asyncio
async def test_generate_pqc_migration_plan_returns_response():
    from app.services.chat.tools import generate_pqc_migration_plan
    db = MagicMock()
    with patch(
        "app.services.chat.tools.PQCMigrationPlanGenerator",
    ) as gen_cls:
        gen_cls.return_value = MagicMock(
            generate=AsyncMock(return_value=MagicMock(
                model_dump=lambda: {"scope": "project", "items": []},
            ))
        )
        out = await generate_pqc_migration_plan(db, project_id="p1")
    assert out["scope"] == "project"
    assert out["items"] == []


@pytest.mark.asyncio
async def test_list_compliance_reports_returns_metadata():
    from app.services.chat.tools import list_compliance_reports
    db = MagicMock()
    with patch("app.services.chat.tools.ComplianceReportRepository") as repo_cls:
        repo_cls.return_value = MagicMock(
            list=AsyncMock(return_value=[MagicMock(
                model_dump=lambda **kw: {"id": "r1", "status": "completed"},
            )])
        )
        out = await list_compliance_reports(db, project_id="p")
    assert len(out["reports"]) == 1
    assert out["reports"][0]["id"] == "r1"


@pytest.mark.asyncio
async def test_list_policy_audit_entries_returns_timeline():
    from app.services.chat.tools import list_policy_audit_entries
    db = MagicMock()
    with patch("app.services.chat.tools.PolicyAuditRepository") as repo_cls:
        repo_cls.return_value = MagicMock(
            list=AsyncMock(return_value=[MagicMock(
                model_dump=lambda **kw: {"version": 1, "change_summary": "x"},
            )])
        )
        out = await list_policy_audit_entries(db, policy_scope="system")
    assert out["entries"][0]["version"] == 1


@pytest.mark.asyncio
async def test_get_framework_evaluation_summary_returns_counts():
    from app.services.chat.tools import get_framework_evaluation_summary
    db = MagicMock()
    fake_summary = {"passed": 2, "failed": 1, "waived": 0, "not_applicable": 0, "total": 3}
    with patch(
        "app.services.chat.tools.ComplianceReportEngine",
    ) as engine_cls, patch(
        "app.services.chat.tools.FRAMEWORK_REGISTRY",
    ) as registry:
        engine_instance = MagicMock(_gather_inputs=AsyncMock(return_value=MagicMock()))
        engine_cls.return_value = engine_instance
        fake_framework = MagicMock(evaluate=MagicMock(return_value=MagicMock(
            summary=fake_summary, framework_name="NIST SP 800-131A",
        )))
        registry.__getitem__.return_value = fake_framework

        user = MagicMock(id="u1", permissions=frozenset())
        with patch("app.services.chat.tools.ScopeResolver") as scope_cls:
            scope_cls.return_value = MagicMock(
                resolve=AsyncMock(return_value=MagicMock(scope="project", scope_id="p")),
            )
            out = await get_framework_evaluation_summary(
                db, user=user, scope="project", scope_id="p",
                framework="nist-sp-800-131a",
            )
    assert out["summary"]["passed"] == 2
    assert out["framework"] == "nist-sp-800-131a"
