"""The retention sweep deletes expired compliance reports, fails reports a dead pod left unfinished, and keeps the rest."""

from datetime import datetime, timedelta, timezone

import pytest

from app.core.constants import COMPLIANCE_REPORT_STUCK_AFTER_HOURS
from app.models.compliance_report import ComplianceReport
from app.repositories.compliance_report import ComplianceReportRepository
from app.schemas.compliance import ReportFormat, ReportFramework, ReportStatus
from app.services.compliance.retention import sweep_expired_compliance_reports


def _report(*, expires_at=None, status=ReportStatus.COMPLETED, requested_ago=timedelta(days=200)):
    now = datetime.now(timezone.utc)
    return ComplianceReport(
        scope="project",
        scope_id="p",
        framework=ReportFramework.NIST_SP_800_131A,
        format=ReportFormat.JSON,
        status=status,
        requested_by="ownerp",
        requested_at=now - requested_ago,
        completed_at=now - requested_ago if status == ReportStatus.COMPLETED else None,
        summary={"passed": 0, "failed": 0, "waived": 0, "not_applicable": 0, "total": 0},
        expires_at=expires_at,
    )


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_sweep_deletes_only_expired_reports(db):
    repo = ComplianceReportRepository(db)
    expired = _report(expires_at=datetime.now(timezone.utc) - timedelta(days=1))
    expired_failed = _report(status=ReportStatus.FAILED, expires_at=datetime.now(timezone.utc) - timedelta(days=1))
    still_live = _report(expires_at=datetime.now(timezone.utc) + timedelta(days=10))
    no_expiry = _report(expires_at=None)
    for report in (expired, expired_failed, still_live, no_expiry):
        await repo.create(report)

    assert await sweep_expired_compliance_reports(db) == 2

    assert await repo.get_by_id(expired.id) is None
    assert await repo.get_by_id(expired_failed.id) is None
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


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_sweep_fails_reports_left_unfinished_and_frees_their_quota_slot(db):
    repo = ComplianceReportRepository(db)
    threshold = timedelta(hours=COMPLIANCE_REPORT_STUCK_AFTER_HOURS)
    stuck_pending = _report(status=ReportStatus.PENDING, requested_ago=threshold + timedelta(minutes=30))
    stuck_generating = _report(status=ReportStatus.GENERATING, requested_ago=threshold + timedelta(minutes=30))
    running = _report(status=ReportStatus.GENERATING, requested_ago=threshold - timedelta(minutes=30))
    for report in (stuck_pending, stuck_generating, running):
        await repo.create(report)

    assert await sweep_expired_compliance_reports(db) == 0

    for report in (stuck_pending, stuck_generating):
        failed = await repo.get_by_id(report.id)
        assert failed is not None
        assert failed.status == ReportStatus.FAILED
        assert failed.error_message and failed.completed_at and failed.expires_at
    assert (await repo.get_by_id(running.id)).status == ReportStatus.GENERATING
    assert await repo.count_pending_for_user("ownerp") == 1
