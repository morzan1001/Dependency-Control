"""The retention sweep deletes expired compliance reports and keeps the rest."""

from datetime import datetime, timedelta, timezone

import pytest

from app.models.compliance_report import ComplianceReport
from app.repositories.compliance_report import ComplianceReportRepository
from app.schemas.compliance import ReportFormat, ReportFramework, ReportStatus
from app.services.compliance.retention import sweep_expired_compliance_reports


def _report(*, expires_at):
    now = datetime.now(timezone.utc)
    return ComplianceReport(
        scope="project",
        scope_id="p",
        framework=ReportFramework.NIST_SP_800_131A,
        format=ReportFormat.JSON,
        status=ReportStatus.COMPLETED,
        requested_by="ownerp",
        requested_at=now - timedelta(days=200),
        completed_at=now - timedelta(days=200),
        summary={"passed": 0, "failed": 0, "waived": 0, "not_applicable": 0, "total": 0},
        expires_at=expires_at,
    )


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_sweep_deletes_only_expired_reports(db):
    repo = ComplianceReportRepository(db)
    expired = _report(expires_at=datetime.now(timezone.utc) - timedelta(days=1))
    still_live = _report(expires_at=datetime.now(timezone.utc) + timedelta(days=10))
    no_expiry = _report(expires_at=None)
    for report in (expired, still_live, no_expiry):
        await repo.create(report)

    assert await sweep_expired_compliance_reports(db) == 1

    assert await repo.get_by_id(expired.id) is None
    assert await repo.get_by_id(still_live.id) is not None
    assert await repo.get_by_id(no_expiry.id) is not None


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_sweep_is_noop_when_nothing_expired(db):
    repo = ComplianceReportRepository(db)
    future = _report(expires_at=datetime.now(timezone.utc) + timedelta(days=30))
    await repo.create(future)

    assert await sweep_expired_compliance_reports(db) == 0
    assert await repo.get_by_id(future.id) is not None
