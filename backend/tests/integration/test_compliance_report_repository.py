from datetime import datetime, timedelta, timezone

import pytest

from app.models.compliance_report import ComplianceReport
from app.repositories.compliance_report import ComplianceReportRepository
from app.schemas.compliance import ReportFormat, ReportFramework, ReportStatus


@pytest.mark.asyncio
async def test_insert_and_get(db):
    repo = ComplianceReportRepository(db)
    r = ComplianceReport(
        scope="project",
        scope_id="p",
        framework=ReportFramework.NIST_SP_800_131A,
        format=ReportFormat.PDF,
        status=ReportStatus.PENDING,
        requested_by="u1",
        requested_at=datetime.now(timezone.utc),
    )
    await repo.insert(r)
    fetched = await repo.get(r.id)
    assert fetched is not None
    assert fetched.scope_id == "p"


@pytest.mark.asyncio
async def test_update_status(db):
    repo = ComplianceReportRepository(db)
    r = ComplianceReport(
        scope="project",
        scope_id="p",
        framework=ReportFramework.NIST_SP_800_131A,
        format=ReportFormat.PDF,
        status=ReportStatus.PENDING,
        requested_by="u1",
        requested_at=datetime.now(timezone.utc),
    )
    await repo.insert(r)
    await repo.update_status(
        r.id,
        status=ReportStatus.COMPLETED,
        artifact_gridfs_id="gs-1",
        artifact_filename="n.pdf",
        artifact_size_bytes=1024,
        artifact_mime_type="application/pdf",
        summary={"passed": 3, "failed": 1, "waived": 0, "not_applicable": 0, "total": 4},
    )
    fetched = await repo.get(r.id)
    assert fetched.status == ReportStatus.COMPLETED
    assert fetched.artifact_gridfs_id == "gs-1"
    assert fetched.summary["passed"] == 3


@pytest.mark.asyncio
async def test_list_by_scope_and_status(db):
    repo = ComplianceReportRepository(db)
    for i in range(3):
        await repo.insert(
            ComplianceReport(
                scope="user",
                scope_id=None,
                framework=ReportFramework.BSI_TR_02102,
                format=ReportFormat.CSV,
                status=ReportStatus.COMPLETED,
                requested_by="u1",
                requested_at=datetime.now(timezone.utc),
            )
        )
    listed = await repo.list(scope="user", limit=10)
    assert len(listed) == 3


@pytest.mark.asyncio
async def test_concurrent_pending_count(db):
    repo = ComplianceReportRepository(db)
    for _ in range(5):
        await repo.insert(
            ComplianceReport(
                scope="user",
                framework=ReportFramework.BSI_TR_02102,
                format=ReportFormat.CSV,
                status=ReportStatus.PENDING,
                requested_by="u-x",
                requested_at=datetime.now(timezone.utc),
            )
        )
    count = await repo.count_pending_for_user("u-x")
    assert count == 5


def _report(*, status, requested_by="u1", requested_at=None, scope_id=None):
    return ComplianceReport(
        scope="project",
        scope_id=scope_id,
        framework=ReportFramework.BSI_TR_02102,
        format=ReportFormat.CSV,
        status=status,
        requested_by=requested_by,
        requested_at=requested_at or datetime.now(timezone.utc),
    )


@pytest.mark.asyncio
async def test_count_pending_for_user_counts_a_report_already_generating(db):
    """A report the worker picked up still occupies the user's rate-limit slot until it finishes."""
    repo = ComplianceReportRepository(db)
    await repo.insert(_report(status=ReportStatus.PENDING, requested_by="u-y"))
    await repo.insert(_report(status=ReportStatus.GENERATING, requested_by="u-y"))
    await repo.insert(_report(status=ReportStatus.COMPLETED, requested_by="u-y"))
    await repo.insert(_report(status=ReportStatus.FAILED, requested_by="u-y"))

    assert await repo.count_pending_for_user("u-y") == 2


@pytest.mark.asyncio
async def test_list_returns_newest_requested_first(db):
    repo = ComplianceReportRepository(db)
    base = datetime(2026, 3, 1, 9, 0, tzinfo=timezone.utc)
    oldest = _report(status=ReportStatus.COMPLETED, requested_at=base, scope_id="p-order")
    newest = _report(status=ReportStatus.COMPLETED, requested_at=base + timedelta(hours=2), scope_id="p-order")
    middle = _report(status=ReportStatus.COMPLETED, requested_at=base + timedelta(hours=1), scope_id="p-order")
    for report in (oldest, newest, middle):
        await repo.insert(report)

    listed = await repo.list(scope="project", scope_id="p-order", limit=10)

    assert [r.id for r in listed] == [newest.id, middle.id, oldest.id]
