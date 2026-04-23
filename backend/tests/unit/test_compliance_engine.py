from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.models.compliance_report import ComplianceReport
from app.schemas.compliance import ReportFormat, ReportFramework, ReportStatus
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

    with patch(
        "app.services.compliance.engine.ComplianceReportRepository",
        return_value=MagicMock(update_status=update_mock, get=AsyncMock(return_value=report)),
    ), patch.object(engine, "_gather_inputs", new=AsyncMock(return_value=MagicMock())
    ), patch.object(engine, "_render", return_value=(b"{}", "x.json", "application/json")
    ), patch.object(engine, "_store_artifact", new=AsyncMock(return_value="gs-1")):
        await engine.generate(report=report, db=db, user=user)

    assert update_mock.call_count >= 2
    final_call = update_mock.call_args_list[-1]
    assert final_call.kwargs.get("status") == ReportStatus.COMPLETED


@pytest.mark.asyncio
async def test_engine_marks_failed_on_exception():
    db = MagicMock()
    update_mock = AsyncMock()
    engine = ComplianceReportEngine()
    report = _report()
    user = MagicMock(id="u1", permissions=frozenset())

    with patch(
        "app.services.compliance.engine.ComplianceReportRepository",
        return_value=MagicMock(update_status=update_mock, get=AsyncMock(return_value=report)),
    ), patch.object(engine, "_gather_inputs", new=AsyncMock(side_effect=RuntimeError("boom"))):
        await engine.generate(report=report, db=db, user=user)

    final_call = update_mock.call_args_list[-1]
    assert final_call.kwargs.get("status") == ReportStatus.FAILED
    assert "boom" in (final_call.kwargs.get("error_message") or "")
