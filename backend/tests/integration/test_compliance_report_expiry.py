"""Expiry and deletion remove a report with its artifact, so neither its metadata nor its download is served."""

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock

import pytest
from bson import ObjectId

from app.api.v1.endpoints import compliance_reports
from app.core.permissions import Permissions
from app.models.compliance_report import ComplianceReport
from app.models.user import User
from app.repositories.compliance_report import ComplianceReportRepository
from app.schemas.compliance import ReportFormat, ReportFramework, ReportStatus
from app.services.compliance.retention import sweep_expired_compliance_reports
from app.services.crypto_policy.seeder import seed_crypto_policies
from app.services.notifications.service import notification_service

_REPORTS = "/api/v1/compliance/reports"


async def _generated_report(db, monkeypatch) -> ComplianceReport:
    monkeypatch.setattr(notification_service, "notify_project_members", AsyncMock())
    await seed_crypto_policies(db)
    report = ComplianceReport(
        scope="project",
        scope_id="p",
        framework=ReportFramework.NIST_SP_800_131A,
        format=ReportFormat.JSON,
        status=ReportStatus.PENDING,
        requested_by="ownerp",
        requested_at=datetime.now(timezone.utc),
    )
    repo = ComplianceReportRepository(db)
    await repo.create(report)
    owner = User(id="ownerp", username="ownerp", email="ownerp@corp.com", permissions=[Permissions.PROJECT_READ])
    await compliance_reports._run_and_webhook(db, report, owner)
    return await repo.get_by_id(report.id)


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_an_expired_report_is_swept_with_its_artifact(client, db, owner_auth_headers_proj, monkeypatch):
    report = await _generated_report(db, monkeypatch)
    served = await client.get(f"{_REPORTS}/{report.id}/download", headers=owner_auth_headers_proj)
    assert (served.status_code, served.json()["framework"]) == (200, "nist-sp-800-131a")

    await db[ComplianceReportRepository.collection_name].update_one(
        {"_id": report.id}, {"$set": {"expires_at": datetime.now(timezone.utc) - timedelta(days=1)}}
    )
    assert await sweep_expired_compliance_reports(db) == 1

    assert (await client.get(f"{_REPORTS}/{report.id}", headers=owner_auth_headers_proj)).status_code == 404
    assert (await client.get(f"{_REPORTS}/{report.id}/download", headers=owner_auth_headers_proj)).status_code == 404
    assert await db["fs.files"].count_documents({"_id": ObjectId(report.artifact_gridfs_id)}) == 0


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_deleting_a_report_deletes_its_artifact(client, db, owner_auth_headers_proj, monkeypatch):
    report = await _generated_report(db, monkeypatch)

    resp = await client.delete(f"{_REPORTS}/{report.id}", headers=owner_auth_headers_proj)

    assert resp.status_code == 204
    assert await db["fs.files"].count_documents({"_id": ObjectId(report.artifact_gridfs_id)}) == 0
