"""Expiry and deletion stop serving a report at once; the orphan reaper frees its artifact afterwards."""

from datetime import datetime, timedelta, timezone

import pytest
from bson import ObjectId

from app.repositories.compliance_report import ComplianceReportRepository
from app.services.compliance.retention import sweep_expired_compliance_reports
from app.services.gridfs_maintenance import reap_orphan_gridfs_files
from tests.helpers.compliance import generated_report

_REPORTS = "/api/v1/compliance/reports"


async def _expire(client, db, report_id, headers) -> None:
    await db[ComplianceReportRepository.collection_name].update_one(
        {"_id": report_id}, {"$set": {"expires_at": datetime.now(timezone.utc) - timedelta(days=1)}}
    )
    assert await sweep_expired_compliance_reports(db) == 1


async def _delete(client, db, report_id, headers) -> None:
    assert (await client.delete(f"{_REPORTS}/{report_id}", headers=headers)).status_code == 204


@pytest.mark.asyncio
@pytest.mark.live_mongo
@pytest.mark.parametrize("remove", [_expire, _delete], ids=["expired", "deleted"])
async def test_a_deleted_or_expired_report_artifact_is_reaped(client, db, owner_auth_headers_proj, monkeypatch, remove):
    report = await generated_report(db, monkeypatch)
    served = await client.get(f"{_REPORTS}/{report.id}/download", headers=owner_auth_headers_proj)
    assert (served.status_code, served.json()["framework"]) == (200, "nist-sp-800-131a")
    artifact = {"_id": ObjectId(report.artifact_gridfs_id)}

    await remove(client, db, report.id, owner_auth_headers_proj)
    kept = await db["fs.files"].count_documents(artifact)
    monkeypatch.setattr("app.services.gridfs_maintenance.ARCHIVE_ORPHAN_MIN_AGE_HOURS", -1)
    await reap_orphan_gridfs_files(db)

    assert (await client.get(f"{_REPORTS}/{report.id}", headers=owner_auth_headers_proj)).status_code == 404
    assert (await client.get(f"{_REPORTS}/{report.id}/download", headers=owner_auth_headers_proj)).status_code == 404
    assert (kept, await db["fs.files"].count_documents(artifact)) == (1, 0)
