"""Expiry tests for compliance reports.

When a report's artifact has been pruned (`artifact_gridfs_id` is None) but
metadata remains, `GET /reports/{id}` should still succeed while
`GET /reports/{id}/download` should return 410 Gone.
"""

from datetime import datetime, timedelta, timezone

import pytest

from app.models.compliance_report import ComplianceReport
from app.repositories.compliance_report import ComplianceReportRepository
from app.schemas.compliance import ReportFormat, ReportFramework, ReportStatus


@pytest.mark.asyncio
async def test_expired_artifact_returns_410(
    client, db, owner_auth_headers_proj,
):
    report = ComplianceReport(
        scope="project", scope_id="p",
        framework=ReportFramework.NIST_SP_800_131A,
        format=ReportFormat.JSON,
        status=ReportStatus.COMPLETED,
        requested_by="ownerp",
        requested_at=datetime.now(timezone.utc) - timedelta(days=200),
        completed_at=datetime.now(timezone.utc) - timedelta(days=200),
        artifact_gridfs_id=None,
        summary={"passed": 0, "failed": 0, "waived": 0, "not_applicable": 0, "total": 0},
        expires_at=datetime.now(timezone.utc) - timedelta(days=100),
    )
    await ComplianceReportRepository(db).insert(report)

    get = await client.get(
        f"/api/v1/compliance/reports/{report.id}",
        headers=owner_auth_headers_proj,
    )
    assert get.status_code == 200

    dl = await client.get(
        f"/api/v1/compliance/reports/{report.id}/download",
        headers=owner_auth_headers_proj,
    )
    assert dl.status_code == 410
