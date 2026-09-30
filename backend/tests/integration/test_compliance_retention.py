"""The retention sweep deletes expired compliance reports together with their GridFS artifacts."""

import logging
from datetime import datetime, timedelta, timezone

import pytest
from bson import ObjectId
from motor.motor_asyncio import AsyncIOMotorGridFSBucket

from app.models.compliance_report import ComplianceReport
from app.repositories.compliance_report import ComplianceReportRepository
from app.schemas.compliance import ReportFormat, ReportFramework, ReportStatus
from app.services.compliance.retention import sweep_expired_compliance_reports

_RETENTION_LOGGER = "app.services.compliance.retention"


def _report(*, expires_at, gridfs_id=None):
    now = datetime.now(timezone.utc)
    return ComplianceReport(
        scope="project",
        scope_id="p",
        framework=ReportFramework.NIST_SP_800_131A,
        format=ReportFormat.JSON,
        status=ReportStatus.COMPLETED,
        requested_by="ownerp",
        requested_at=now - timedelta(days=200),
        completed_at=now - timedelta(days=200),
        artifact_gridfs_id=gridfs_id,
        summary={"passed": 0, "failed": 0, "waived": 0, "not_applicable": 0, "total": 0},
        expires_at=expires_at,
    )


def _expired(gridfs_id):
    return _report(expires_at=datetime.now(timezone.utc) - timedelta(days=1), gridfs_id=gridfs_id)


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_sweep_deletes_expired_reports_and_their_artifacts(db):
    repo = ComplianceReportRepository(db)
    gridfs_id = str(await AsyncIOMotorGridFSBucket(db).upload_from_stream("report.json", b"{}"))
    expired = _expired(gridfs_id)
    still_live = _report(expires_at=datetime.now(timezone.utc) + timedelta(days=10))
    no_expiry = _report(expires_at=None)
    for report in (expired, still_live, no_expiry):
        await repo.create(report)

    assert await sweep_expired_compliance_reports(db) == 1

    assert await repo.get_by_id(expired.id) is None
    assert await repo.get_by_id(still_live.id) is not None
    assert await repo.get_by_id(no_expiry.id) is not None
    assert await db["fs.files"].count_documents({"_id": ObjectId(gridfs_id)}) == 0


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_sweep_is_noop_when_nothing_expired(db):
    repo = ComplianceReportRepository(db)
    future = _report(expires_at=datetime.now(timezone.utc) + timedelta(days=30))
    await repo.create(future)

    assert await sweep_expired_compliance_reports(db) == 0
    assert await repo.get_by_id(future.id) is not None


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_an_artifact_the_sweep_cannot_delete_is_logged_as_a_warning(db, caplog):
    await ComplianceReportRepository(db).create(_expired("not-an-object-id"))

    with caplog.at_level(logging.DEBUG, logger=_RETENTION_LOGGER):
        assert await sweep_expired_compliance_reports(db) == 1

    assert [r.levelno for r in caplog.records if "not-an-object-id" in r.getMessage()] == [logging.WARNING]


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_an_artifact_already_gone_is_no_warning(db, caplog):
    await ComplianceReportRepository(db).create(_expired(str(ObjectId())))

    with caplog.at_level(logging.DEBUG, logger=_RETENTION_LOGGER):
        assert await sweep_expired_compliance_reports(db) == 1

    assert not [r for r in caplog.records if r.levelno >= logging.WARNING]
