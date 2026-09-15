"""Integration tests for compliance-report endpoint authorization."""

from datetime import datetime, timezone

import pytest

from app.models.compliance_report import ComplianceReport
from app.repositories.compliance_report import ComplianceReportRepository
from app.schemas.compliance import ReportFormat, ReportFramework, ReportStatus

_MEMBER_USER_ID = "testuser"
_OTHER_USER_ID = "another-user"


async def _insert_report(
    db,
    *,
    requested_by: str,
    scope: str = "user",
    scope_id: str | None = None,
    status: ReportStatus = ReportStatus.COMPLETED,
) -> str:
    report = ComplianceReport(
        scope=scope,
        scope_id=scope_id,
        framework=ReportFramework.BSI_TR_02102,
        format=ReportFormat.JSON,
        status=status,
        requested_by=requested_by,
        requested_at=datetime.now(timezone.utc),
    )
    await ComplianceReportRepository(db).insert(report)
    return report.id


async def _listed_ids(client, headers) -> list[str]:
    resp = await client.get("/api/v1/compliance/reports?limit=100", headers=headers)
    assert resp.status_code == 200, resp.text
    return [r["_id"] for r in resp.json()["reports"]]


@pytest.mark.asyncio
async def test_unauth_request_blocked(client, db):
    resp = await client.post(
        "/api/v1/compliance/reports",
        json={"scope": "project", "scope_id": "p", "framework": "nist-sp-800-131a", "format": "json"},
    )
    assert resp.status_code in (401, 403)


@pytest.mark.asyncio
async def test_global_scope_requires_admin(
    client,
    db,
    admin_auth_headers,
    member_auth_headers,
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
    client,
    db,
    owner_auth_headers_proj,
):
    repo = ComplianceReportRepository(db)
    for _ in range(10):
        await repo.insert(
            ComplianceReport(
                scope="project",
                scope_id="p",
                framework=ReportFramework.BSI_TR_02102,
                format=ReportFormat.JSON,
                status=ReportStatus.PENDING,
                requested_by="ownerp",
                requested_at=datetime.now(timezone.utc),
            )
        )

    resp = await client.post(
        "/api/v1/compliance/reports",
        json={"scope": "project", "scope_id": "p", "framework": "bsi-tr-02102", "format": "json"},
        headers=owner_auth_headers_proj,
    )
    assert resp.status_code == 429, resp.text


@pytest.mark.asyncio
async def test_get_report_is_404_for_a_caller_outside_its_scope(client, db, member_auth_headers):
    """404 rather than 403 so the endpoint does not confirm that someone else's report exists."""
    own = await _insert_report(db, requested_by=_MEMBER_USER_ID)
    foreign = await _insert_report(db, requested_by=_OTHER_USER_ID)

    mine = await client.get(f"/api/v1/compliance/reports/{own}", headers=member_auth_headers)
    assert mine.status_code == 200, mine.text

    theirs = await client.get(f"/api/v1/compliance/reports/{foreign}", headers=member_auth_headers)
    assert theirs.status_code == 404, theirs.text


@pytest.mark.asyncio
async def test_list_reports_hides_another_users_user_scoped_report(client, db, member_auth_headers):
    own = await _insert_report(db, requested_by=_MEMBER_USER_ID)
    foreign = await _insert_report(db, requested_by=_OTHER_USER_ID)

    ids = await _listed_ids(client, member_auth_headers)

    assert own in ids
    assert foreign not in ids


@pytest.mark.asyncio
async def test_list_reports_hides_a_project_report_the_caller_cannot_reach(client, db, member_auth_headers):
    own = await _insert_report(db, requested_by=_MEMBER_USER_ID)
    unreachable = await _insert_report(
        db,
        requested_by=_OTHER_USER_ID,
        scope="project",
        scope_id="foreign-project",
    )

    ids = await _listed_ids(client, member_auth_headers)

    assert own in ids
    assert unreachable not in ids


@pytest.mark.asyncio
async def test_list_reports_hides_global_reports_from_a_caller_without_global_analytics(
    client,
    db,
    member_auth_headers,
    admin_auth_headers,
):
    own = await _insert_report(db, requested_by=_MEMBER_USER_ID)
    global_report = await _insert_report(db, requested_by="admin-user", scope="global")

    member_ids = await _listed_ids(client, member_auth_headers)
    assert own in member_ids
    assert global_report not in member_ids

    assert global_report in await _listed_ids(client, admin_auth_headers)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "status",
    [ReportStatus.PENDING, ReportStatus.GENERATING, ReportStatus.FAILED],
)
async def test_download_is_409_until_the_report_is_completed(client, db, member_auth_headers, status):
    report_id = await _insert_report(db, requested_by=_MEMBER_USER_ID, status=status)

    resp = await client.get(f"/api/v1/compliance/reports/{report_id}/download", headers=member_auth_headers)

    assert resp.status_code == 409, resp.text
    assert status.value in resp.json()["detail"]
