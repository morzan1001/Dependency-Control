"""Integration tests for compliance-report endpoint authorization."""

from datetime import datetime, timezone
from unittest.mock import patch

import pytest

from app.core.permissions import Permissions
from app.models.compliance_report import ComplianceReport
from app.repositories.compliance_report import ComplianceReportRepository
from app.schemas.compliance import ReportFormat, ReportFramework, ReportStatus
from app.services.analytics import scopes
from tests.helpers.auth import bearer_headers

_MEMBER_USER_ID = "testuser"
_OTHER_USER_ID = "another-user"
_WRITE_SUPERUSER = ("editor-at-large", [Permissions.PROJECT_READ, Permissions.PROJECT_UPDATE])


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
    await ComplianceReportRepository(db).create(report)
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
        await repo.create(
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
async def test_a_project_write_superuser_lists_a_project_report_outside_its_membership(client, db):
    await db.projects.insert_one({"_id": "p-foreign", "name": "p-foreign", "members": []})
    report = await _insert_report(db, requested_by=_OTHER_USER_ID, scope="project", scope_id="p-foreign")

    assert report in await _listed_ids(client, bearer_headers(*_WRITE_SUPERUSER))


@pytest.mark.asyncio
async def test_a_project_write_superuser_opens_a_project_report_outside_its_membership(client, db):
    await db.projects.insert_one({"_id": "p-foreign", "name": "p-foreign", "members": []})
    report = await _insert_report(db, requested_by=_OTHER_USER_ID, scope="project", scope_id="p-foreign")

    resp = await client.get(f"/api/v1/compliance/reports/{report}", headers=bearer_headers(*_WRITE_SUPERUSER))

    assert resp.status_code == 200, resp.text


@pytest.mark.asyncio
async def test_a_read_all_caller_lists_project_reports_past_the_analytics_project_ceiling(client, db):
    await db.projects.insert_one({"_id": "p-2", "name": "p-2", "members": []})
    report = await _insert_report(db, requested_by=_OTHER_USER_ID, scope="project", scope_id="p-2")

    with patch.object(scopes, "ANALYTICS_MAX_SCOPE_PROJECTS", 1):
        ids = await _listed_ids(client, bearer_headers("reader", [Permissions.PROJECT_READ_ALL]))

    assert report in ids


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_a_member_lists_its_projects_reports_unless_it_asks_for_personal_ones(
    client, db, member_auth_headers, _project
):
    report = await _insert_report(db, requested_by=_OTHER_USER_ID, scope="project", scope_id=str(_project.id))

    assert report in await _listed_ids(client, member_auth_headers)
    personal = await client.get("/api/v1/compliance/reports?scope=user", headers=member_auth_headers)
    assert personal.status_code == 200, personal.text
    assert report not in [r["_id"] for r in personal.json()["reports"]]


@pytest.mark.asyncio
async def test_listing_personal_reports_reads_none_of_the_callers_projects(client, db, member_auth_headers):
    await db.projects.insert_one(
        {"_id": "p-2", "name": "p-2", "members": [{"user_id": _MEMBER_USER_ID, "role": "viewer"}]}
    )
    own = await _insert_report(db, requested_by=_MEMBER_USER_ID)

    with patch.object(scopes, "ANALYTICS_MAX_SCOPE_PROJECTS", 1):
        resp = await client.get("/api/v1/compliance/reports?scope=user", headers=member_auth_headers)

    assert resp.status_code == 200, resp.text
    assert [r["_id"] for r in resp.json()["reports"]] == [own]


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
