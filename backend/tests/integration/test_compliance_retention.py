"""Integration test for the compliance-report retention sweeper.

`expires_at` is set on every completed report but was never read before —
GridFS and the metadata collection grew unbounded. The sweeper deletes
expired documents (and best-effort their GridFS blobs).
"""

from datetime import datetime, timedelta, timezone

import pytest

from app.models.compliance_report import ComplianceReport
from app.repositories.compliance_report import ComplianceReportRepository
from app.schemas.compliance import ReportFormat, ReportFramework, ReportStatus
from app.services.compliance.retention import sweep_expired_compliance_reports


def _report(*, expires_at, gridfs_id=None):
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
        artifact_gridfs_id=gridfs_id,
        summary={"passed": 0, "failed": 0, "waived": 0, "not_applicable": 0, "total": 0},
        expires_at=expires_at,
    )


@pytest.mark.asyncio
async def test_sweep_deletes_expired_reports(db):
    repo = ComplianceReportRepository(db)
    now = datetime.now(timezone.utc)

    expired = _report(expires_at=now - timedelta(days=1), gridfs_id="gs-expired")
    still_live = _report(expires_at=now + timedelta(days=10))
    no_expiry = _report(expires_at=None)

    await repo.insert(expired)
    await repo.insert(still_live)
    await repo.insert(no_expiry)

    deleted = await sweep_expired_compliance_reports(db)
    assert deleted == 1

    assert await repo.get(expired.id) is None
    assert await repo.get(still_live.id) is not None
    assert await repo.get(no_expiry.id) is not None


@pytest.mark.asyncio
async def test_sweep_is_noop_when_nothing_expired(db):
    repo = ComplianceReportRepository(db)
    future = _report(expires_at=datetime.now(timezone.utc) + timedelta(days=30))
    await repo.insert(future)

    deleted = await sweep_expired_compliance_reports(db)
    assert deleted == 0
    assert await repo.get(future.id) is not None
