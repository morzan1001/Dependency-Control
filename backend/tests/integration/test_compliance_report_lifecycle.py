from datetime import datetime, timezone

import pytest
import pytest_asyncio

from app.api.v1.endpoints import compliance_reports
from app.models.compliance_report import (
    ComplianceReport,
    EvaluationCoverage,
    ReportFormat,
    ReportFramework,
    ReportStatus,
)
from app.repositories.compliance_report import ComplianceReportRepository
from app.services.chat.tools import ChatToolRegistry
from app.services.compliance.renderers.base import coverage_statement
from tests.helpers.auth import make_admin
from tests.helpers.compliance import generated_report

ADMIN = make_admin()
# The third project report outlived its project.
SCOPES = {
    "r-shop": ("project", "p-shop"),
    "r-mail": ("project", "p-mail"),
    "r-gone": ("project", "p-gone"),
    "r-core": ("team", "t-core"),
    "r-ops": ("team", "t-ops"),
    "r-global": ("global", None),
    "r-user": ("user", None),
}
NAMED = {"r-shop": "shop", "r-mail": "mail", "r-core": "Core", "r-ops": "Ops"}


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


@pytest_asyncio.fixture
async def scoped_reports(db):
    await db.projects.insert_many([{"_id": "p-shop", "name": "shop"}, {"_id": "p-mail", "name": "mail"}])
    await db.teams.insert_many([{"_id": "t-core", "name": "Core", "members": []}, {"_id": "t-ops", "name": "Ops"}])
    for report_id, (scope, scope_id) in SCOPES.items():
        report = ComplianceReport(
            id=report_id,
            scope=scope,
            scope_id=scope_id,
            framework=ReportFramework.BSI_TR_02102,
            format=ReportFormat.JSON,
            status=ReportStatus.COMPLETED,
            requested_by=ADMIN.id,
            requested_at=datetime.now(timezone.utc),
        )
        await ComplianceReportRepository(db).create(report)
    return db


def _scopes_shown(reports: list[dict]) -> dict[str, tuple[str | None, str | None]]:
    return {r["_id"]: (r["scope_id"], r.get("scope_name")) for r in reports}


EXPECTED_SCOPES = {report_id: (scope_id, NAMED.get(report_id)) for report_id, (_, scope_id) in SCOPES.items()}


async def _list(db) -> list[dict]:
    result = await compliance_reports.list_reports(
        ADMIN, db, scope=None, scope_id=None, framework=None, status=None, skip=0, limit=50
    )
    return result["reports"]


@pytest.mark.asyncio
async def test_the_list_names_each_project_and_team_beside_its_id(scoped_reports):
    assert _scopes_shown(await _list(scoped_reports)) == EXPECTED_SCOPES


@pytest.mark.asyncio
async def test_the_list_names_every_scope_with_one_read_per_scope_kind(scoped_reports):
    by_id: list[str] = []
    for name in ("projects", "teams"):
        collection = scoped_reports[name]
        find = collection.find

        def recording_find(query=None, *args, _find=find, _name=name, **kwargs):
            if "_id" in (query or {}):
                by_id.append(_name)
            return _find(query, *args, **kwargs)

        collection.find = recording_find

    await _list(scoped_reports)

    assert sorted(by_id) == ["projects", "teams"]


@pytest.mark.asyncio
@pytest.mark.parametrize("report_id", ["r-shop", "r-core", "r-global"])
async def test_one_report_names_its_scope_beside_its_id(scoped_reports, report_id):
    report = await compliance_reports.get_report(report_id, ADMIN, scoped_reports)

    assert _scopes_shown([report]) == {report_id: EXPECTED_SCOPES[report_id]}


@pytest.mark.asyncio
async def test_the_chat_report_list_names_each_project_and_team_beside_its_id(scoped_reports):
    result = await ChatToolRegistry().execute_tool("list_compliance_reports", {}, ADMIN, scoped_reports)

    assert _scopes_shown(result["reports"]) == EXPECTED_SCOPES


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_a_project_report_names_the_project_and_keeps_its_id_for_machines(
    client, db, owner_auth_headers_proj, monkeypatch
):
    report = await generated_report(db, monkeypatch)

    served = await client.get(f"/api/v1/compliance/reports/{report.id}/download", headers=owner_auth_headers_proj)

    assert report.artifact_filename.startswith("nist-sp-800-131a_project-project-p_")
    assert served.headers["content-disposition"] == f'attachment; filename="{report.artifact_filename}"'
    assert (served.json()["scope_description"], served.json()["scope"]) == (
        "project 'project-p'",
        {"kind": "project", "id": "p"},
    )
