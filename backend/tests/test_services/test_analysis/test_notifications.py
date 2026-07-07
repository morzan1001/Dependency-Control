"""Tests for scan-completion notification building/sending.

Covers two audit findings for app/services/analysis/notifications.py:

  #1 (elegance): the private inverted SEVERITY_ORDER map was replaced with the
     canonical app.core.constants.get_severity_value. The top-priority sort must
     still order most-severe-first (as a tiebreak after KEV and EPSS).
  #2 (bug): the plain-text "View full report" line must contain the report URL,
     not the raw scan UUID.
"""

from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from app.core.config import settings
from app.services.analysis import notifications
from app.services.analysis.notifications import (
    _build_vulnerability_message,
    send_scan_notifications,
)


# ---------------------------------------------------------------------------
# _build_vulnerability_message — finding #2 (report URL, not raw scan_id)
# ---------------------------------------------------------------------------


class TestBuildVulnerabilityMessageReportLink:
    def test_view_full_report_uses_url_not_raw_uuid(self):
        """The 'View full report' line must render the passed report URL."""
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
        # A bare UUID with no scheme/path must NOT be what we emit.
        assert "View full report: 3f2a-uuid" not in message


# ---------------------------------------------------------------------------
# send_scan_notifications — end-to-end message assembly
# ---------------------------------------------------------------------------


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
    """Drive send_scan_notifications, returning the vulnerability_found message."""
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

    with patch.object(notifications, "notification_service", fake_notify), patch.object(
        notifications, "webhook_service", fake_webhook
    ):
        await send_scan_notifications(
            scan_id="scan-abc-123",
            project=project,
            aggregated_findings=findings,
            results_summary=["osv: ok"],
            db=_FakeDB(),
        )
    return captured


class TestSendScanNotificationsMessage:
    @pytest.mark.asyncio
    async def test_report_link_is_full_url(self):
        """finding #2: the emitted message links to the full scan URL."""
        findings = [_finding("CVE-1", "CRITICAL")]
        captured = await _capture_vuln_message(findings)
        expected = f"{settings.FRONTEND_BASE_URL}/projects/proj-1/scans/scan-abc-123"
        assert f"View full report: {expected}" in captured["message"]
        assert "View full report: scan-abc-123" not in captured["message"]

    @pytest.mark.asyncio
    async def test_top_vulns_sorted_most_severe_first(self):
        """finding #1: with equal KEV/EPSS, severity orders most-severe-first."""
        findings = [
            _finding("CVE-LOW", "LOW"),
            _finding("CVE-CRIT", "CRITICAL"),
            _finding("CVE-HIGH", "HIGH"),
        ]
        captured = await _capture_vuln_message(findings)
        msg = captured["message"]
        # Only CRITICAL/HIGH are in critical_vulns; both should appear, CRIT first.
        crit_idx = msg.index("CVE-CRIT")
        high_idx = msg.index("CVE-HIGH")
        assert crit_idx < high_idx

    @pytest.mark.asyncio
    async def test_kev_sorts_before_more_severe_non_kev(self):
        """KEV remains the primary sort key ahead of raw severity."""
        findings = [
            _finding("CVE-CRIT", "CRITICAL"),
            _finding("CVE-KEVHIGH", "HIGH", in_kev=True),
        ]
        captured = await _capture_vuln_message(findings)
        msg = captured["message"]
        assert msg.index("CVE-KEVHIGH") < msg.index("CVE-CRIT")
