"""A report is shown or served only to a caller whose scope resolves, and a database failure is not a refusal."""

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import BackgroundTasks, HTTPException
from pymongo.errors import ServerSelectionTimeoutError

from app.api.v1.endpoints import compliance_reports
from app.core.permissions import Permissions
from app.models.compliance_report import ComplianceReport
from app.models.user import User
from app.repositories.compliance_report import ComplianceReportRepository
from app.repositories.projects import ProjectRepository
from app.schemas.compliance import ReportFormat, ReportFramework, ReportStatus

_DB_DOWN = ServerSelectionTimeoutError("no primary")


def _user(user_id: str = "u-1", *permissions: str) -> User:
    return User(
        id=user_id,
        username=user_id,
        email=f"{user_id}@corp.com",
        permissions=list(permissions or [Permissions.PROJECT_READ]),
    )


async def _stored_report(db, *, scope: str, scope_id: str | None, requested_by: str = "u-1") -> str:
    report = ComplianceReport(
        scope=scope,
        scope_id=scope_id,
        framework=ReportFramework.BSI_TR_02102,
        format=ReportFormat.JSON,
        status=ReportStatus.COMPLETED,
        requested_by=requested_by,
        requested_at=datetime.now(timezone.utc),
        artifact_gridfs_id="65f000000000000000000001",
        artifact_filename="report.json",
    )
    await ComplianceReportRepository(db).insert(report)
    return report.id


def _artifact_store():
    bucket = MagicMock()
    bucket.open_download_stream = AsyncMock(return_value=MagicMock(readchunk=AsyncMock(return_value=b"")))
    return patch.object(compliance_reports, "AsyncIOMotorGridFSBucket", return_value=bucket)


def _project_gate_fails():
    return patch.object(ProjectRepository, "get_by_id", AsyncMock(side_effect=_DB_DOWN))


@pytest.mark.asyncio
async def test_a_database_failure_while_creating_a_report_is_not_a_403(db):
    request = compliance_reports.ReportRequest(
        scope="project", scope_id="p-1", framework=ReportFramework.BSI_TR_02102, format=ReportFormat.JSON
    )
    with _project_gate_fails(), pytest.raises(ServerSelectionTimeoutError):
        await compliance_reports.create_report(request, BackgroundTasks(), _user(), db)


@pytest.mark.asyncio
async def test_a_database_failure_while_reading_a_report_is_not_a_404(db):
    report_id = await _stored_report(db, scope="project", scope_id="p-1")
    with _project_gate_fails(), pytest.raises(ServerSelectionTimeoutError):
        await compliance_reports.get_report(report_id, _user(), db)


@pytest.mark.asyncio
async def test_a_database_failure_while_downloading_a_report_is_not_a_403(db):
    report_id = await _stored_report(db, scope="project", scope_id="p-1")
    with _project_gate_fails(), pytest.raises(ServerSelectionTimeoutError):
        await compliance_reports.download_report(report_id, _user(), db)


@pytest.mark.asyncio
async def test_another_users_personal_report_is_not_served(db):
    report_id = await _stored_report(db, scope="user", scope_id=None, requested_by="u-owner")
    with _artifact_store(), pytest.raises(HTTPException) as refused:
        await compliance_reports.download_report(report_id, _user("u-other"), db)

    assert refused.value.status_code == 404


@pytest.mark.asyncio
async def test_a_team_report_is_downloaded_by_a_member_but_not_by_a_team_reader_outside_the_team(db):
    await db.teams.insert_one({"_id": "t-1", "name": "Alpha", "members": [{"user_id": "u-1", "role": "member"}]})
    await db.projects.insert_one({"_id": "p-1", "name": "p-1", "team_ids": ["t-1"], "members": []})
    report_id = await _stored_report(db, scope="team", scope_id="t-1")

    with _artifact_store():
        served = await compliance_reports.download_report(
            report_id, _user("u-1", Permissions.TEAM_READ, Permissions.PROJECT_READ), db
        )
        with pytest.raises(HTTPException) as refused:
            await compliance_reports.download_report(
                report_id, _user("u-out", Permissions.TEAM_READ_ALL, Permissions.PROJECT_READ), db
            )

    assert served.status_code == 200
    assert refused.value.status_code == 404
