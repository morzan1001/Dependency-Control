"""Scan-completion notification building/sending: top-priority sort ordering and report-URL rendering."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from app.core.config import settings
from app.core.constants import EPSS_HIGH_THRESHOLD, NOTIFICATION_EVENT_ANALYSIS_COMPLETED
from app.models.project import Project, ProjectMember
from app.services.analysis import notifications
from app.services.analysis.notifications import (
    _build_vulnerability_message,
    send_scan_notifications,
)
from app.services.notifications import notification_service
from tests.mocks.fake_mongo import FakeDatabase


class TestBuildVulnerabilityMessageReportLink:
    def test_view_full_report_uses_url_not_raw_uuid(self):
        scan_link = "https://app.example.com/projects/p1/scans/3f2a-uuid"
        _subject, message = _build_vulnerability_message(
            "proj",
            kev_vulns=[],
            high_epss_vulns=[],
            priority_vulns=[{"severity": "CRITICAL"}],
            top_vulns=[],
            scan_link=scan_link,
        )
        assert f"View full report: {scan_link}" in message
        # a bare UUID with no scheme/path must not be emitted
        assert "View full report: 3f2a-uuid" not in message


def _finding(fid, severity, epss=None, in_kev=False, aliases=None):
    details = {"id": fid, "severity": severity, "aliases": aliases or []}
    if epss is not None:
        details["epss_score"] = epss
    if in_kev:
        details["in_kev"] = True
    return SimpleNamespace(
        id=fid,
        type="vulnerability",
        severity=severity,
        component="pkg",
        version="1.0.0",
        model_dump=lambda details=details, fid=fid, severity=severity: {
            "type": "vulnerability",
            "severity": severity,
            "component": "pkg",
            "version": "1.0.0",
            "id": f"pkg:1.0.0:{fid}",
            "details": {"vulnerabilities": [details]},
        },
    )


async def _db_with_scan(scan_id: str = "scan-abc-123") -> FakeDatabase:
    db = FakeDatabase()
    await db.scans.insert_one({"_id": scan_id, "status": "completed"})
    return db


async def _capture_vuln_message(findings):
    """Drive send_scan_notifications and return the vulnerability_found message and webhook call."""
    project = Project(id="proj-1", name="MyProject")
    captured = {}

    async def _notify(**kwargs):
        if kwargs.get("event_type") == "vulnerability_found":
            captured["message"] = kwargs["message"]
            captured["subject"] = kwargs["subject"]

    fake_notify = SimpleNamespace(notify_project_members=AsyncMock(side_effect=_notify))
    fake_webhook = SimpleNamespace(
        trigger_scan_completed=AsyncMock(),
        trigger_vulnerability_found=AsyncMock(),
    )

    with (
        patch.object(notifications, "notification_service", fake_notify),
        patch.object(notifications, "webhook_service", fake_webhook),
    ):
        await send_scan_notifications(
            scan_id="scan-abc-123",
            project=project,
            aggregated_findings=findings,
            results_summary=["osv: ok"],
            db=await _db_with_scan(),
        )
    webhook_call = fake_webhook.trigger_vulnerability_found.call_args
    captured["webhook"] = webhook_call.kwargs if webhook_call else None
    return captured


class TestSendScanNotificationsMessage:
    @pytest.mark.asyncio
    async def test_report_link_is_full_url(self):
        findings = [_finding("CVE-1", "CRITICAL")]
        captured = await _capture_vuln_message(findings)
        expected = f"{settings.FRONTEND_BASE_URL}/projects/proj-1/scans/scan-abc-123"
        assert f"View full report: {expected}" in captured["message"]
        assert "View full report: scan-abc-123" not in captured["message"]

    @pytest.mark.asyncio
    async def test_top_vulns_sorted_most_severe_first(self):
        """With equal KEV/EPSS, severity orders most-severe-first."""
        findings = [
            _finding("CVE-LOW", "LOW"),
            _finding("CVE-CRIT", "CRITICAL"),
            _finding("CVE-HIGH", "HIGH"),
        ]
        captured = await _capture_vuln_message(findings)
        msg = captured["message"]
        # the LOW entry is no priority; both priorities appear, CRIT first
        crit_idx = msg.index("CVE-CRIT")
        high_idx = msg.index("CVE-HIGH")
        assert crit_idx < high_idx

    @pytest.mark.asyncio
    async def test_kev_sorts_before_more_severe_non_kev(self):
        findings = [
            _finding("CVE-CRIT", "CRITICAL"),
            _finding("CVE-KEVHIGH", "HIGH", in_kev=True),
        ]
        captured = await _capture_vuln_message(findings)
        msg = captured["message"]
        assert msg.index("CVE-KEVHIGH") < msg.index("CVE-CRIT")

    @pytest.mark.asyncio
    async def test_a_vulnerability_at_the_epss_threshold_counts_as_high_risk(self):
        """EPSS_HIGH_THRESHOLD is defined as "exploitation probability at or above 10%", so a score
        sitting exactly on it is the alert's whole reason to exist here: nothing else is severe."""
        findings = [_finding("CVE-EPSS", "MEDIUM", epss=EPSS_HIGH_THRESHOLD)]

        captured = await _capture_vuln_message(findings)

        assert "High-Risk Vulnerabilities in MyProject" in captured.get("subject", "")
        assert "[HIGH RISK] 1 vulnerabilities" in captured["message"]
        assert captured["webhook"]["high_epss_count"] == 1


class TestPriorityVulnerabilities:
    @pytest.mark.asyncio
    async def test_a_medium_kev_is_counted_and_listed_as_priority(self):
        captured = await _capture_vuln_message([_finding("CVE-KEV", "MEDIUM", in_kev=True)])
        assert "Priority (Critical/High/KEV/High EPSS): 1" in captured["message"]
        assert "CVE-KEV" in captured["message"]
        assert (captured["webhook"]["critical_count"], captured["webhook"]["kev_count"]) == (0, 1)

    @pytest.mark.asyncio
    async def test_an_alert_raised_by_high_epss_lists_what_raised_it(self):
        captured = await _capture_vuln_message([_finding("CVE-EPSS", "MEDIUM", epss=0.5)])
        assert "Top Priority Vulnerabilities (1 of 1)" in captured["message"]
        assert "CVE-EPSS" in captured["message"]

    @pytest.mark.asyncio
    async def test_the_high_epss_line_names_the_threshold_it_counts_by(self):
        captured = await _capture_vuln_message([_finding("CVE-EPSS", "MEDIUM", epss=EPSS_HIGH_THRESHOLD)])
        assert "(EPSS >= 10%)" in captured["message"]

    @pytest.mark.asyncio
    async def test_an_advisory_is_alerted_under_its_cve(self):
        ghsa = _finding("GHSA-35jh-r3h4-6jhm", "HIGH", aliases=["CVE-2021-23337"])
        captured = await _capture_vuln_message([ghsa])
        assert "CVE-2021-23337" in captured["message"]
        assert "GHSA-35jh-r3h4-6jhm" not in captured["message"]


class TestVulnerabilityWebhookCounters:
    @pytest.mark.asyncio
    async def test_the_webhook_counts_criticals_and_highs_separately(self):
        """Downstream consumers page on critical_count; a scan of two CRITICALs must not report
        them as anything else."""
        findings = [
            _finding("CVE-CRIT-1", "CRITICAL"),
            _finding("CVE-CRIT-2", "CRITICAL"),
            _finding("CVE-HIGH-1", "HIGH"),
        ]

        captured = await _capture_vuln_message(findings)

        assert captured["webhook"]["critical_count"] == 2
        assert captured["webhook"]["high_count"] == 1


class TestAnalysisCompletedSeverityCounts:
    @pytest.mark.asyncio
    async def test_a_scanner_error_is_not_counted_as_a_high_finding(self):
        findings = [
            SimpleNamespace(type="system_warning", severity="HIGH"),
            SimpleNamespace(type="vulnerability", severity="CRITICAL"),
        ]
        blocks = patch.object(notifications, "build_analysis_completed_blocks", return_value=[])
        fake_notify = SimpleNamespace(notify_project_members=AsyncMock())
        fake_webhook = SimpleNamespace(trigger_scan_completed=AsyncMock())
        with (
            blocks as build_blocks,
            patch.object(notifications, "notification_service", fake_notify),
            patch.object(notifications, "webhook_service", fake_webhook),
        ):
            await send_scan_notifications(
                scan_id="scan-abc-123",
                project=Project(id="proj-1", name="MyProject"),
                aggregated_findings=findings,
                results_summary=["osv: Partial"],
                db=await _db_with_scan(),
            )
        assert build_blocks.call_args.kwargs["severity_counts"] == {"CRITICAL": 1, "HIGH": 0, "MEDIUM": 0, "LOW": 0}


class TestAnalysisCompletedReachesSubscribers:
    @pytest.mark.asyncio
    async def test_a_member_subscribed_to_analysis_completed_is_emailed(self):
        """The event name is the key a member's preferences are looked up under, so one the
        preference sanitizer does not know silently reaches nobody."""
        db = await _db_with_scan()
        await db.users.insert_one(
            {
                "_id": "user-1",
                "username": "dev",
                "email": "dev@example.com",
                "is_active": True,
            }
        )
        project = Project(
            _id="proj-1",
            name="MyProject",
            members=[
                ProjectMember(
                    user_id="user-1",
                    role="admin",
                    notification_preferences={NOTIFICATION_EVENT_ANALYSIS_COMPLETED: ["email"]},
                )
            ],
        )
        send = AsyncMock()

        with (
            patch.object(notification_service.email_provider, "send", send),
            patch.object(notifications, "webhook_service", SimpleNamespace(trigger_scan_completed=AsyncMock())),
        ):
            await send_scan_notifications(
                scan_id="scan-abc-123",
                project=project,
                aggregated_findings=[],
                results_summary=["osv: ok"],
                db=db,
            )

        send.assert_awaited_once()
        assert send.await_args.args[0] == "dev@example.com"
        assert "Analysis Completed: MyProject" in send.await_args.args[1]


def _sast_finding(fid):
    return SimpleNamespace(id=fid, type="sast", severity="HIGH", component="app.py", version="")


async def _announce_twice(first, second):
    """Two analyses of one scan, as a late scanner result that reopens it produces."""
    db = await _db_with_scan()
    project = Project(id="proj-1", name="MyProject")
    notify = SimpleNamespace(notify_project_members=AsyncMock())
    webhooks = SimpleNamespace(trigger_scan_completed=AsyncMock(), trigger_vulnerability_found=AsyncMock())
    with (
        patch.object(notifications, "notification_service", notify),
        patch.object(notifications, "webhook_service", webhooks),
    ):
        for findings in (first, second):
            await send_scan_notifications("scan-abc-123", project, findings, ["osv: ok"], db)
    events = [call.kwargs["event_type"] for call in notify.notify_project_members.await_args_list]
    return events, webhooks


class TestReAnalysisAnnouncements:
    @pytest.mark.asyncio
    async def test_an_unchanged_re_analysis_announces_nothing_again(self):
        events, webhooks = await _announce_twice([_finding("CVE-1", "CRITICAL")], [_finding("CVE-1", "CRITICAL")])

        assert events == ["analysis_completed", "vulnerability_found"]
        assert webhooks.trigger_scan_completed.await_count == 1
        assert webhooks.trigger_vulnerability_found.await_count == 1

    @pytest.mark.asyncio
    async def test_a_late_sast_result_reports_the_completion_but_does_not_repeat_the_alert(self):
        events, webhooks = await _announce_twice(
            [_finding("CVE-1", "CRITICAL")], [_finding("CVE-1", "CRITICAL"), _sast_finding("SAST-1")]
        )

        assert events == ["analysis_completed", "vulnerability_found", "analysis_completed"]
        assert webhooks.trigger_scan_completed.await_count == 2
        assert webhooks.trigger_vulnerability_found.await_count == 1

    @pytest.mark.asyncio
    async def test_a_new_vulnerability_alerts_again(self):
        events, webhooks = await _announce_twice(
            [_finding("CVE-1", "CRITICAL")], [_finding("CVE-1", "CRITICAL"), _finding("CVE-2", "HIGH")]
        )

        assert events.count("vulnerability_found") == 2
        assert webhooks.trigger_vulnerability_found.await_count == 2


class TestScanWebhookScope:
    @pytest.mark.asyncio
    async def test_both_scan_events_reach_the_owning_teams_webhooks(self):
        db = await _db_with_scan()
        await db.webhooks.insert_one(
            {
                "_id": "team-hook",
                "url": "https://example.com/team",
                "team_id": "alpha",
                "project_id": None,
                "events": ["scan.completed", "vulnerability.found"],
                "is_active": True,
            }
        )
        project = Project(id="proj-1", name="MyProject", team_ids=["alpha"])
        send = AsyncMock(return_value=True)

        with (
            patch.object(notifications, "notification_service", SimpleNamespace(notify_project_members=AsyncMock())),
            patch.object(notifications.webhook_service, "_send_webhook", send),
        ):
            await send_scan_notifications("scan-abc-123", project, [_finding("CVE-1", "CRITICAL")], ["osv: ok"], db)

        assert [(c.args[1].id, c.args[3]) for c in send.await_args_list] == [
            ("team-hook", "scan.completed"),
            ("team-hook", "vulnerability.found"),
        ]
