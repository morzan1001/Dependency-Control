"""A finished report job announces itself: the webhook carries the final status, members hear only of a ready report."""

from datetime import datetime, timezone
from unittest.mock import AsyncMock

import pytest

from app.api.v1.endpoints import compliance_reports
from app.core.constants import WEBHOOK_EVENT_COMPLIANCE_REPORT_GENERATED
from app.core.permissions import Permissions
from app.models.compliance_report import ComplianceReport
from app.models.project import Project, ProjectMember
from app.models.user import User
from app.models.webhook import Webhook
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


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_a_team_report_reaches_the_teams_own_webhooks(db, monkeypatch):
    team_hook = Webhook(
        team_id="team-a", url="https://hooks.example/a", events=[WEBHOOK_EVENT_COMPLIANCE_REPORT_GENERATED]
    )
    other_hook = Webhook(
        team_id="team-b", url="https://hooks.example/b", events=[WEBHOOK_EVENT_COMPLIANCE_REPORT_GENERATED]
    )
    for hook in (team_hook, other_hook):
        await db.webhooks.insert_one(hook.model_dump(by_alias=True))
    delivered = AsyncMock(return_value=True)
    monkeypatch.setattr(webhook_service, "_send_webhook", delivered)
    monkeypatch.setattr(ComplianceReportEngine, "generate", AsyncMock(return_value=(ReportStatus.COMPLETED, {})))
    report = ComplianceReport(
        scope="team",
        scope_id="team-a",
        framework=ReportFramework.BSI_TR_02102,
        format=ReportFormat.JSON,
        status=ReportStatus.PENDING,
        requested_by="ownerp",
        requested_at=datetime.now(timezone.utc),
    )

    await compliance_reports._run_and_webhook(db, report, _user("ownerp"))

    assert [call.args[1].id for call in delivered.await_args_list] == [team_hook.id]
