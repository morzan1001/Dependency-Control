from datetime import datetime, timezone

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
