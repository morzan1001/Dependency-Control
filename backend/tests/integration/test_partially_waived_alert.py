"""A security alert is built from the advisories of a finding that no per-CVE waiver covers."""

import copy
from unittest.mock import AsyncMock, patch

import pytest

from app.core.constants import NOTIFICATION_EVENT_VULNERABILITY_FOUND, SCAN_STATUS_COMPLETED
from app.models.project import Project
from app.models.stats import Stats
from app.services.aggregation import ResultAggregator
from app.services.analysis import engine, notifications

_SCAN_ID = "scan-1"
_LOG4SHELL = "CVE-2021-44228"
_LOG4J_DOS = "CVE-2021-45105"


def _log4j_record() -> dict:
    """The engine's in-memory record of log4j-core with Log4Shell enriched as KEV, before any waiver is stamped."""
    vulnerabilities = [
        {"VulnerabilityID": cve, "PkgName": "log4j-core", "InstalledVersion": "2.14.1", "Severity": severity}
        for cve, severity in ((_LOG4SHELL, "CRITICAL"), (_LOG4J_DOS, "HIGH"))
    ]
    aggregator = ResultAggregator()
    aggregator.aggregate("trivy", {"Results": [{"Target": "app", "Vulnerabilities": vulnerabilities}]})
    [record], _ = engine._prepare_finding_records(aggregator.get_findings(), _SCAN_ID, "proj-1", None)
    record["details"]["vulnerabilities"][0]["in_kev"] = True
    return record


@pytest.mark.asyncio
@pytest.mark.live_mongo
async def test_a_waived_advisory_of_a_partly_waived_finding_drives_no_alert(db):
    record = _log4j_record()
    stored = copy.deepcopy(record)
    stored["details"]["vulnerabilities"][0].update(waived=True, waiver_reason="Not loaded by the app")
    await db.findings.insert_one(stored)
    await db.scans.insert_one({"_id": _SCAN_ID, "status": "completed"})
    notify, vulnerability_found = AsyncMock(), AsyncMock()

    with (
        patch.object(notifications.notification_service, "notify_project_members", notify),
        patch.object(notifications.webhook_service, "trigger_scan_completed", AsyncMock()),
        patch.object(notifications.webhook_service, "trigger_vulnerability_found", vulnerability_found),
    ):
        live = await engine._filter_out_waived_findings([record], _SCAN_ID, db)
        await notifications.send_scan_notifications(
            _SCAN_ID, Project(id="proj-1", name="shop"), live, Stats(), SCAN_STATUS_COMPLETED, [], {}, 1, db
        )

    [alert] = [
        c.kwargs for c in notify.await_args_list if c.kwargs["event_type"] == NOTIFICATION_EVENT_VULNERABILITY_FOUND
    ]
    assert "KEV" not in alert["subject"]
    announced = vulnerability_found.await_args.kwargs
    assert announced["kev_count"] == 0
    assert [vulnerability["id"] for vulnerability in announced["top_vulnerabilities"]] == [_LOG4J_DOS]
