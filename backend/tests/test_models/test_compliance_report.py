from datetime import datetime, timezone

from app.models.compliance_report import ComplianceReport
from app.schemas.compliance import ReportFormat, ReportFramework, ReportStatus


def test_minimal_instance():
    r = ComplianceReport(
        scope="project",
        scope_id="p1",
        framework=ReportFramework.NIST_SP_800_131A,
        format=ReportFormat.PDF,
        status=ReportStatus.PENDING,
        requested_by="u1",
        requested_at=datetime.now(timezone.utc),
    )
    assert r.id
    assert r.status == ReportStatus.PENDING
    assert r.artifact_gridfs_id is None
