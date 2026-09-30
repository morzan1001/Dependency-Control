"""A finished report job announces its own outcome: the webhook carries the final status, members hear only of a ready report."""

from datetime import datetime, timezone
from unittest.mock import AsyncMock

import pytest

from app.api.v1.endpoints import compliance_reports
from app.core.permissions import Permissions
from app.models.compliance_report import ComplianceReport
from app.models.project import Project, ProjectMember
from app.models.user import User
from app.repositories.compliance_report import ComplianceReportRepository
from app.schemas.compliance import ReportFormat, ReportFramework, ReportStatus
from app.services.compliance.engine import ComplianceReportEngine
from app.services.crypto_policy.seeder import seed_crypto_policies
from app.services.notifications.service import notification_service
from app.services.webhooks import webhook_service


@pytest.fixture
def deliveries(monkeypatch):
    webhooks, notifications = AsyncMock(), AsyncMock()
    monkeypatch.setattr(webhook_service, "trigger_webhooks", webhooks)
    monkeypatch.setattr(notification_service, "notify_project_members", notifications)
    return webhooks, notifications


def _user(user_id: str) -> User:
    return User(id=user_id, username=user_id, email=f"{user_id}@corp.com", permissions=[Permissions.PROJECT_READ])


async def _project_report(db, *, requested_by: str) -> ComplianceReport:
    project = Project(id="p", name="project-p", members=[ProjectMember(user_id="ownerp", role="admin")])
    await db.projects.insert_one(project.model_dump(by_alias=True))
    report = ComplianceReport(
        scope="project",
        scope_id="p",
        framework=ReportFramework.BSI_TR_02102,
        format=ReportFormat.JSON,
        status=ReportStatus.PENDING,
        requested_by=requested_by,
        requested_at=datetime.now(timezone.utc),
    )
    await ComplianceReportRepository(db).create(report)
    return report


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_a_completed_report_announces_its_summary_and_tells_the_members(db, deliveries):
    webhooks, notifications = deliveries
    await seed_crypto_policies(db)
    report = await _project_report(db, requested_by="ownerp")

    await compliance_reports._run_and_webhook(db, report, _user("ownerp"))

    stored = await ComplianceReportRepository(db).get_by_id(report.id)
    assert stored.status == ReportStatus.COMPLETED
    payload = webhooks.await_args.kwargs["payload"]
    assert (payload["status"], payload["summary"]) == ("completed", stored.summary)
    _project, _event, subject, *_ = notifications.await_args.args
    assert subject == "Compliance report ready (bsi-tr-02102)"


@pytest.mark.asyncio
async def test_a_failed_report_announces_failed_and_tells_no_member_it_is_ready(db, deliveries):
    """The requester left the project before the job ran, so its scope no longer resolves."""
    webhooks, notifications = deliveries
    report = await _project_report(db, requested_by="former-member")

    await compliance_reports._run_and_webhook(db, report, _user("former-member"))

    assert webhooks.await_args.kwargs["payload"]["status"] == "failed"
    notifications.assert_not_awaited()


@pytest.mark.asyncio
async def test_a_report_gone_after_its_job_crashed_announces_nothing(db, deliveries, monkeypatch):
    webhooks, notifications = deliveries
    report = await _project_report(db, requested_by="ownerp")

    async def _crash_after_delete(self, *, report, db, user):
        await ComplianceReportRepository(db).delete(report.id)
        raise RuntimeError("status write lost")

    monkeypatch.setattr(ComplianceReportEngine, "generate", _crash_after_delete)

    await compliance_reports._run_and_webhook(db, report, _user("ownerp"))

    webhooks.assert_not_awaited()
    notifications.assert_not_awaited()
