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
            critical_vulns=[{"severity": "CRITICAL"}],
            top_vulns=[],
            scan_link=scan_link,
        )
        assert f"View full report: {scan_link}" in message
        # a bare UUID with no scheme/path must not be emitted
        assert "View full report: 3f2a-uuid" not in message


def _finding(fid, severity, epss=None, in_kev=False):
    details = {"severity": severity}
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
            "id": fid,
            "type": "vulnerability",
            "severity": severity,
            "component": "pkg",
            "version": "1.0.0",
            "details": {"vulnerabilities": [details]},
        },
    )


class _FakeScans:
    async def find_one(self, *_args, **_kwargs):
        return None


class _FakeDB:
    scans = _FakeScans()


async def _capture_vuln_message(findings):
    """Drive send_scan_notifications and return the vulnerability_found message and webhook call."""
    project = SimpleNamespace(id="proj-1", name="MyProject")
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
            db=_FakeDB(),
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
        # only CRITICAL/HIGH are in critical_vulns; both appear, CRIT first
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


class TestAnalysisCompletedReachesSubscribers:
    @pytest.mark.asyncio
    async def test_a_member_subscribed_to_analysis_completed_is_emailed(self):
        """The event name is the key a member's preferences are looked up under, so one the
        preference sanitizer does not know silently reaches nobody."""
        db = FakeDatabase()
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
