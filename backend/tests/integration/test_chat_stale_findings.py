"""get_stale_findings ages a head-build finding by the first_seen_at ingest persists, the date the CVE SLA
report reads, so a finding whose first scans retention deleted still counts as old."""

from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio

from app.core import ensure_utc
from app.core.constants import SCAN_STATUS_COMPLETED
from app.models.finding import Finding, FindingType, Severity
from app.models.project import Project, Scan
from app.models.user import User
from app.repositories.findings import FindingRepository
from app.repositories.scans import ScanRepository
from app.services.analysis.engine import _persist_findings_and_waivers, _prepare_finding_records
from app.services.chat.tools import ChatToolRegistry
from tests.helpers.permission_presets import PRESET_ADMIN

# The value is unread: the marker on the second case makes the ``db`` fixture hand out a real server.
_DATABASES = [
    pytest.param("attrappe", id="attrappe"),
    pytest.param("real-mongo", marks=pytest.mark.live_mongo, id="real-mongo"),
]

pytestmark = [pytest.mark.asyncio, pytest.mark.parametrize("database", _DATABASES)]

_PROJECT = "p-stale"
_HEAD = "scan-head"
# Whole seconds, so the server's millisecond precision cannot move the dates the tests compare.
_NOW = datetime.now(timezone.utc).replace(microsecond=0)
_LONG_AGO = _NOW - timedelta(days=200)


def _vulnerability(component: str, version: str, severity: Severity) -> Finding:
    return Finding(
        id=f"{component}:{version}",
        type=FindingType.VULNERABILITY,
        severity=severity,
        component=component,
        version=version,
        description="known vulnerable release",
        scanners=["trivy"],
    )


_LOG4J = _vulnerability("log4j-core", "2.14.1", Severity.CRITICAL)
_COMMONS_TEXT = _vulnerability("commons-text", "1.9", Severity.MEDIUM)
_JACKSON = _vulnerability("jackson-databind", "2.13.0", Severity.HIGH)


async def _build(db, scan_id: str, created_at: datetime, *findings: Finding) -> None:
    await ScanRepository(db).create(
        Scan(id=scan_id, project_id=_PROJECT, branch="main", status=SCAN_STATUS_COMPLETED, created_at=created_at)
    )
    records, _ = _prepare_finding_records(list(findings), scan_id, _PROJECT, created_at)
    await _persist_findings_and_waivers(records, scan_id, _PROJECT, FindingRepository(db), db)


async def _stale(db, **args) -> dict:
    admin = User(id="admin-1", username="admin", email="admin@test.com", permissions=list(PRESET_ADMIN))
    return await ChatToolRegistry().execute_tool("get_stale_findings", {"project_id": _PROJECT, **args}, admin, db)


@pytest_asyncio.fixture
async def history(db):
    """log4j and commons-text first built 200 days ago, jackson new in head, the first build retention-deleted."""
    project = Project(id=_PROJECT, name="stale-project", default_branch="main", latest_scan_id=_HEAD)
    await db.projects.insert_one(project.model_dump(by_alias=True))
    await _build(db, "scan-first", _LONG_AGO, _LOG4J, _COMMONS_TEXT)
    await _build(db, _HEAD, _NOW, _LOG4J, _COMMONS_TEXT, _JACKSON)
    await db.findings.delete_many({"scan_id": "scan-first"})
    await db.scans.delete_many({"_id": "scan-first"})
    return db


async def test_a_finding_first_seen_before_the_window_is_stale_after_retention(history, database):
    result = await _stale(history, days_open=30)

    (row,) = result["findings"]
    assert row["finding_id"] == _LOG4J.id
    assert ensure_utc(datetime.fromisoformat(row["first_seen_at"])) == _LONG_AGO


async def test_a_lower_severity_threshold_admits_the_old_medium(history, database):
    result = await _stale(history, days_open=30, severity_min="MEDIUM")

    assert {row["finding_id"] for row in result["findings"]} == {_LOG4J.id, _COMMONS_TEXT.id}


async def test_nothing_is_stale_when_the_window_reaches_past_first_detection(history, database):
    result = await _stale(history, days_open=365)

    assert result["findings"] == []
