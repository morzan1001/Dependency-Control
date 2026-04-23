from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.models.compliance_report import ComplianceReport
from app.schemas.compliance import ReportFormat, ReportFramework, ReportStatus
from app.services.analytics.scopes import ResolvedScope
from app.services.compliance.engine import ComplianceReportEngine


def _report(**overrides):
    base = dict(
        scope="user", scope_id=None,
        framework=ReportFramework.NIST_SP_800_131A,
        format=ReportFormat.JSON,
        status=ReportStatus.PENDING,
        requested_by="u1", requested_at=datetime.now(timezone.utc),
    )
    base.update(overrides)
    return ComplianceReport(**base)


@pytest.mark.asyncio
async def test_engine_marks_report_completed_on_success():
    db = MagicMock()
    update_mock = AsyncMock()
    engine = ComplianceReportEngine()
    report = _report()
    user = MagicMock(id="u1", permissions=frozenset())

    inputs = MagicMock(policy_version=1, iana_catalog_version=2)
    evaluation = MagicMock(summary={"total": 0})
    # Use spec=["evaluate"] so hasattr(fw, "evaluate_async") is False — the
    # engine dispatches on that attribute (async path is exercised by the
    # PQC framework unit test).
    fw = MagicMock(spec=["evaluate"])
    fw.evaluate = MagicMock(return_value=evaluation)

    resolver = MagicMock(resolve=AsyncMock(return_value=ResolvedScope(
        scope="user", scope_id=None, project_ids=[])))

    with patch(
        "app.services.compliance.engine.ComplianceReportRepository",
        return_value=MagicMock(update_status=update_mock, get=AsyncMock(return_value=report)),
    ), patch(
        "app.services.compliance.engine.ScopeResolver",
        return_value=resolver,
    ), patch.dict(
        "app.services.compliance.engine.FRAMEWORK_REGISTRY",
        {ReportFramework.NIST_SP_800_131A: fw},
        clear=False,
    ), patch.object(engine, "_gather_inputs", new=AsyncMock(return_value=inputs)
    ), patch.object(engine, "_render", return_value=(b"{}", "x.json", "application/json")
    ), patch.object(engine, "_store_artifact", new=AsyncMock(return_value="gs-1")):
        await engine.generate(report=report, db=db, user=user)

    assert update_mock.call_count >= 2
    final_call = update_mock.call_args_list[-1]
    assert final_call.kwargs.get("status") == ReportStatus.COMPLETED


@pytest.mark.asyncio
async def test_engine_awaits_evaluate_async_when_available():
    """Regression: the PQC framework is async-only. The engine must dispatch
    on hasattr(framework, "evaluate_async") and await it, not call .evaluate
    synchronously (which raises RuntimeError on the PQC framework)."""
    db = MagicMock()
    update_mock = AsyncMock()
    engine = ComplianceReportEngine()
    report = _report()
    user = MagicMock(id="u1", permissions=frozenset())

    inputs = MagicMock(policy_version=1, iana_catalog_version=2)
    evaluation = MagicMock(summary={"total": 0})
    fw = MagicMock(spec=["evaluate_async"])
    fw.evaluate_async = AsyncMock(return_value=evaluation)

    resolver = MagicMock(resolve=AsyncMock(return_value=ResolvedScope(
        scope="user", scope_id=None, project_ids=[])))

    with patch(
        "app.services.compliance.engine.ComplianceReportRepository",
        return_value=MagicMock(update_status=update_mock, get=AsyncMock(return_value=report)),
    ), patch(
        "app.services.compliance.engine.ScopeResolver",
        return_value=resolver,
    ), patch.dict(
        "app.services.compliance.engine.FRAMEWORK_REGISTRY",
        {ReportFramework.NIST_SP_800_131A: fw},
        clear=False,
    ), patch.object(engine, "_gather_inputs", new=AsyncMock(return_value=inputs)
    ), patch.object(engine, "_render", return_value=(b"{}", "x.json", "application/json")
    ), patch.object(engine, "_store_artifact", new=AsyncMock(return_value="gs-1")):
        await engine.generate(report=report, db=db, user=user)

    fw.evaluate_async.assert_awaited_once()
    final_call = update_mock.call_args_list[-1]
    assert final_call.kwargs.get("status") == ReportStatus.COMPLETED


@pytest.mark.asyncio
async def test_engine_marks_failed_on_exception():
    db = MagicMock()
    update_mock = AsyncMock()
    engine = ComplianceReportEngine()
    report = _report()
    user = MagicMock(id="u1", permissions=frozenset())

    resolver = MagicMock(resolve=AsyncMock(side_effect=RuntimeError("boom")))
    with patch(
        "app.services.compliance.engine.ComplianceReportRepository",
        return_value=MagicMock(update_status=update_mock, get=AsyncMock(return_value=report)),
    ), patch(
        "app.services.compliance.engine.ScopeResolver",
        return_value=resolver,
    ):
        await engine.generate(report=report, db=db, user=user)

    final_call = update_mock.call_args_list[-1]
    assert final_call.kwargs.get("status") == ReportStatus.FAILED
    assert "boom" in (final_call.kwargs.get("error_message") or "")


@pytest.mark.asyncio
async def test_engine_gather_inputs_builds_evaluation_input():
    db = MagicMock()
    scan_aggregate = MagicMock()

    async def scan_agg_iter():
        yield {"_id": "p1", "scan_id": "s1"}

    scan_aggregate.__aiter__ = lambda self: scan_agg_iter()
    db.scans.aggregate = MagicMock(return_value=scan_aggregate)

    db.scans.find_one = AsyncMock(return_value={"project_id": "p1"})

    asset_repo_mock = MagicMock(list_by_scan=AsyncMock(return_value=[]))

    findings_cursor = MagicMock()

    async def findings_iter():
        if False:
            yield None
        return

    findings_cursor.__aiter__ = lambda self: findings_iter()
    find_mock = MagicMock(limit=MagicMock(return_value=findings_cursor))
    db.findings.find = MagicMock(return_value=find_mock)

    policy_repo_mock = MagicMock(get_system_policy=AsyncMock(return_value=None))

    resolved = ResolvedScope(scope="user", scope_id=None, project_ids=["p1"])
    report = MagicMock()
    report.scope = "user"
    report.scope_id = None

    engine = ComplianceReportEngine()
    with patch(
        "app.services.compliance.engine.CryptoAssetRepository",
        return_value=asset_repo_mock,
    ), patch(
        "app.services.compliance.engine.CryptoPolicyRepository",
        return_value=policy_repo_mock,
    ):
        result = await engine._gather_inputs(db, resolved, report)

    assert result.resolved is resolved
    assert "user scope" in result.scope_description
    assert result.scan_ids == ["s1"]
