"""HTTP contract and job-document transitions for compliance report lifecycle endpoints."""

from datetime import datetime, timezone

import pytest

from app.models.compliance_report import ComplianceReport
from app.repositories.compliance_report import ComplianceReportRepository
from app.schemas.compliance import EvaluationCoverage, ReportFormat, ReportFramework, ReportStatus
from app.services.compliance.renderers.base import coverage_statement


@pytest.mark.asyncio
async def test_list_reports(client, db, owner_auth_headers_proj):
    for _ in range(2):
        resp = await client.post(
            "/api/v1/compliance/reports",
            json={"scope": "project", "scope_id": "p", "framework": "bsi-tr-02102", "format": "csv"},
            headers=owner_auth_headers_proj,
        )
        assert resp.status_code == 202, resp.text
    resp = await client.get(
        "/api/v1/compliance/reports?scope=project&scope_id=p&limit=10",
        headers=owner_auth_headers_proj,
    )
    assert resp.status_code == 200
    assert len(resp.json()["reports"]) == 2


@pytest.mark.asyncio
async def test_delete_report(client, db, owner_auth_headers_proj):
    resp = await client.post(
        "/api/v1/compliance/reports",
        json={"scope": "project", "scope_id": "p", "framework": "cnsa-2.0", "format": "json"},
        headers=owner_auth_headers_proj,
    )
    assert resp.status_code == 202, resp.text
    report_id = resp.json()["report_id"]
    dele = await client.delete(
        f"/api/v1/compliance/reports/{report_id}",
        headers=owner_auth_headers_proj,
    )
    assert dele.status_code == 204
    followup = await client.get(
        f"/api/v1/compliance/reports/{report_id}",
        headers=owner_auth_headers_proj,
    )
    assert followup.status_code == 404


@pytest.mark.asyncio
async def test_a_report_is_served_with_the_coverage_sentence_its_artifact_prints(client, db, member_auth_headers):
    gapped, bare = (
        ComplianceReport(
            scope="user",
            framework=ReportFramework.CVE_REMEDIATION_SLA,
            format=ReportFormat.PDF,
            status=ReportStatus.COMPLETED,
            requested_by="testuser",
            requested_at=datetime.now(timezone.utc),
            coverage=coverage,
        )
        for coverage in (EvaluationCoverage(gaps=["project 'payments' has no usable scan"]), None)
    )
    for report in (gapped, bare):
        await ComplianceReportRepository(db).create(report)

    one = await client.get(f"/api/v1/compliance/reports/{gapped.id}", headers=member_auth_headers)
    listed = await client.get("/api/v1/compliance/reports", headers=member_auth_headers)

    statements = {r["_id"]: r["coverage_statement"] for r in listed.json()["reports"]}
    assert one.json()["coverage_statement"] == coverage_statement(gapped.coverage) == statements[gapped.id]
    assert statements[bare.id] is None
