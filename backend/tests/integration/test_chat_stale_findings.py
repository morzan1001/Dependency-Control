"""get_stale_findings ages a head-build finding by its persisted first_seen_at, so scan retention keeps it old."""

from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio

from app.core import ensure_utc
from app.core.constants import SCAN_STATUS_COMPLETED
from app.core.init_db import create_indexes
from app.models.finding import Finding, Severity
from app.models.project import Project, Scan
from app.models.user import User
from app.models.waiver import Waiver
from app.repositories.findings import FindingRepository
from app.repositories.scans import ScanRepository
from app.repositories.waivers import WaiverRepository
from app.services.analysis.engine import _persist_findings_and_waivers, _prepare_finding_records
from app.services.chat.tools import ChatToolRegistry
from tests.helpers.findings import aggregated_vulnerability
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


def _vulnerability(component: str, version: str, cve: str, severity: Severity) -> Finding:
    return aggregated_vulnerability(component, version, {"id": cve, "severity": severity})


_LOG4J = _vulnerability("log4j-core", "2.14.1", "CVE-2021-44228", Severity.CRITICAL)
_COMMONS_TEXT = _vulnerability("commons-text", "1.9", "CVE-2022-42889", Severity.MEDIUM)
_JACKSON = _vulnerability("jackson-databind", "2.13.0", "CVE-2022-42003", Severity.HIGH)

_LOG4SHELL_CRITICAL = {"id": "CVE-2021-44228", "severity": Severity.CRITICAL}
_CONTEXT_LOOKUP_HIGH = {"id": "CVE-2021-45046", "severity": Severity.HIGH}
_CONTEXT_LOOKUP_LOW = {"id": "CVE-2021-45046", "severity": Severity.LOW}


async def _project(db) -> None:
    await create_indexes(db)
    project = Project(id=_PROJECT, name="stale-project", default_branch="main", latest_scan_id=_HEAD)
    await db.projects.insert_one(project.model_dump(by_alias=True))


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
    await _project(db)
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


async def test_a_cve_kept_across_a_version_bump_stays_stale(db, database):
    await _project(db)
    patched = _vulnerability("log4j-core", "2.15.0", "CVE-2021-44228", Severity.CRITICAL)
    await _build(db, "scan-first", _LONG_AGO, _LOG4J)
    await _build(db, _HEAD, _NOW, patched)

    result = await _stale(db, days_open=30)

    (row,) = result["findings"]
    assert row["finding_id"] == patched.id
    assert ensure_utc(datetime.fromisoformat(row["first_seen_at"])) == _LONG_AGO


async def test_a_new_critical_next_to_an_old_low_kept_across_a_bump_is_not_stale(db, database):
    await _project(db)
    await _build(db, "scan-first", _LONG_AGO, aggregated_vulnerability("log4j-core", "2.14.1", _CONTEXT_LOOKUP_LOW))
    patched = aggregated_vulnerability("log4j-core", "2.15.0", _CONTEXT_LOOKUP_LOW, _LOG4SHELL_CRITICAL)
    await _build(db, _HEAD, _NOW, patched)

    assert (await _stale(db, days_open=30))["findings"] == []


async def test_a_new_high_next_to_an_old_waived_critical_is_not_stale(db, database):
    await _project(db)
    await WaiverRepository(db).create(
        Waiver(project_id=_PROJECT, vulnerability_id="CVE-2021-44228", reason="not reachable", created_by="u")
    )
    await _build(db, "scan-first", _LONG_AGO, aggregated_vulnerability("log4j-core", "2.14.1", _LOG4SHELL_CRITICAL))
    patched = aggregated_vulnerability("log4j-core", "2.15.0", _LOG4SHELL_CRITICAL, _CONTEXT_LOOKUP_HIGH)
    await _build(db, _HEAD, _NOW, patched)

    assert (await _stale(db, days_open=30))["findings"] == []


async def test_an_old_high_kept_next_to_a_new_critical_is_named_with_its_own_age(db, database):
    await _project(db)
    await _build(db, "scan-first", _LONG_AGO, aggregated_vulnerability("log4j-core", "2.14.1", _CONTEXT_LOOKUP_HIGH))
    patched = aggregated_vulnerability("log4j-core", "2.15.0", _CONTEXT_LOOKUP_HIGH, _LOG4SHELL_CRITICAL)
    await _build(db, _HEAD, _NOW, patched)

    (row,) = (await _stale(db, days_open=30))["findings"]
    assert (row["cve"], row["severity"]) == ("CVE-2021-45046", "HIGH")
    assert ensure_utc(datetime.fromisoformat(row["first_seen_at"])) == _LONG_AGO


async def test_a_stale_critical_names_the_row_over_an_older_high(db, database):
    await _project(db)
    older_high = {"id": "CVE-2000-0001", "severity": Severity.HIGH}
    await _build(
        db, "scan-first", _NOW - timedelta(days=300), aggregated_vulnerability("log4j-core", "2.14.1", older_high)
    )
    both = aggregated_vulnerability("log4j-core", "2.14.1", older_high, _LOG4SHELL_CRITICAL)
    await _build(db, "scan-second", _LONG_AGO, both)
    await _build(db, _HEAD, _NOW, both)

    (row,) = (await _stale(db, days_open=30))["findings"]
    assert (row["cve"], row["severity"]) == ("CVE-2021-44228", "CRITICAL")
    assert ensure_utc(datetime.fromisoformat(row["first_seen_at"])) == _LONG_AGO


async def test_a_head_finding_stored_without_a_detection_date_ages_from_its_scan(db, database):
    await _project(db)
    built = _NOW - timedelta(days=400)
    await ScanRepository(db).create(
        Scan(id=_HEAD, project_id=_PROJECT, branch="main", status=SCAN_STATUS_COMPLETED, created_at=built)
    )
    # Copies written before 1.9.42 carry no first_seen_at, so they skip the persist that stamps one.
    records, _ = _prepare_finding_records([_LOG4J], _HEAD, _PROJECT, built)
    await db.findings.insert_many(records)

    result = await _stale(db, days_open=30)

    (row,) = result["findings"]
    assert row["finding_id"] == _LOG4J.id
    assert ensure_utc(datetime.fromisoformat(row["first_seen_at"])) == built
