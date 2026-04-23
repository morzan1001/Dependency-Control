"""Integration tests for compliance-report endpoint authorization."""

import pytest


@pytest.mark.asyncio
async def test_unauth_request_blocked(client, db):
    resp = await client.post(
        "/api/v1/compliance/reports",
        json={"scope": "project", "scope_id": "p",
              "framework": "nist-sp-800-131a", "format": "json"},
    )
    assert resp.status_code in (401, 403)


@pytest.mark.asyncio
async def test_global_scope_requires_admin(
    client, db, admin_auth_headers, member_auth_headers,
):
    resp_ok = await client.post(
        "/api/v1/compliance/reports",
        json={"scope": "global", "framework": "nist-sp-800-131a", "format": "json"},
        headers=admin_auth_headers,
    )
    assert resp_ok.status_code == 202, resp_ok.text

    resp_denied = await client.post(
        "/api/v1/compliance/reports",
        json={"scope": "global", "framework": "nist-sp-800-131a", "format": "json"},
        headers=member_auth_headers,
    )
    assert resp_denied.status_code in (401, 403)


@pytest.mark.asyncio
async def test_rate_limit_many_pending(
    client, db, owner_auth_headers_proj,
):
    """Seed 10 pending reports directly, then POST an 11th and expect 429."""
    from datetime import datetime, timezone

    from app.models.compliance_report import ComplianceReport
    from app.repositories.compliance_report import ComplianceReportRepository
    from app.schemas.compliance import ReportFormat, ReportFramework, ReportStatus

    repo = ComplianceReportRepository(db)
    for _ in range(10):
        await repo.insert(ComplianceReport(
            scope="project", scope_id="p",
            framework=ReportFramework.BSI_TR_02102,
            format=ReportFormat.JSON,
            status=ReportStatus.PENDING,
            requested_by="ownerp",
            requested_at=datetime.now(timezone.utc),
        ))

    resp = await client.post(
        "/api/v1/compliance/reports",
        json={"scope": "project", "scope_id": "p",
              "framework": "bsi-tr-02102", "format": "json"},
        headers=owner_auth_headers_proj,
    )
    assert resp.status_code == 429, resp.text
