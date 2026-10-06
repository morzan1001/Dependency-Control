"""Hotspots and impact age a vulnerability from its first detection in the project, which outlives retention."""

from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio

from app.core.init_db import create_indexes
from app.models.finding import Finding, FindingType
from app.repositories.findings import FindingRepository
from app.services.aggregation import ResultAggregator
from app.services.analysis.engine import _persist_findings_and_waivers, _prepare_finding_records

pytestmark = pytest.mark.live_mongo

_PROJECT = "p"
# Whole seconds, so the server's millisecond precision cannot move the dates the tests compare.
_NOW = datetime.now(timezone.utc).replace(microsecond=0)


def _days_ago(days: int) -> datetime:
    return _NOW - timedelta(days=days)


def _vulnerability(component: str, cve: str) -> Finding:
    return Finding(
        id=cve,
        type=FindingType.VULNERABILITY,
        severity="HIGH",
        component=component,
        version="1.0.0",
        description="",
        scanners=["trivy"],
        details={"fixed_version": "1.0.1"},
    )


async def _scan(db, scan_id: str, created_at: datetime, *findings: Finding) -> None:
    await db.scans.insert_one(
        {"_id": scan_id, "project_id": _PROJECT, "status": "completed", "branch": "main", "created_at": created_at}
    )
    aggregator = ResultAggregator()
    for finding in findings:
        aggregator.add_finding(finding)
    records, _ = _prepare_finding_records(aggregator.get_findings(), scan_id, _PROJECT, created_at)
    await _persist_findings_and_waivers(records, scan_id, _PROJECT, FindingRepository(db), db)


@pytest_asyncio.fixture
async def retained(db, owner_auth_headers_proj):
    """lodash was first seen by a scan that retention has since deleted; minimist is new in the head scan."""
    await create_indexes(db)
    await _scan(db, "scan-old", _days_ago(200), _vulnerability("lodash", "CVE-2021-23337"))
    await _scan(
        db,
        "scan-head",
        _days_ago(2),
        _vulnerability("lodash", "CVE-2021-23337"),
        _vulnerability("minimist", "CVE-2021-44906"),
    )
    await db.scans.delete_one({"_id": "scan-old"})
    await db.findings.delete_many({"scan_id": "scan-old"})
    await db.projects.update_one({"_id": _PROJECT}, {"$set": {"latest_scan_id": "scan-head"}})
    return owner_auth_headers_proj


@pytest.mark.asyncio
async def test_hotspot_age_outlives_the_scan_that_first_saw_it(client, retained):
    resp = await client.get("/api/v1/analytics/hotspots", headers=retained)

    assert resp.status_code == 200, resp.text
    by_component = {h["component"]: h for h in resp.json()}
    assert by_component["lodash"]["days_known"] == 200
    assert by_component["lodash"]["first_seen"] == _days_ago(200).isoformat()
    assert by_component["lodash"]["first_seen"].endswith("+00:00")


@pytest.mark.asyncio
async def test_hotspots_sorted_by_first_seen_follow_the_age_they_show(client, retained):
    resp = await client.get(
        "/api/v1/analytics/hotspots", params={"sort_by": "first_seen", "sort_order": "asc"}, headers=retained
    )

    assert resp.status_code == 200, resp.text
    assert [(h["component"], h["days_known"]) for h in resp.json()] == [("lodash", 200), ("minimist", 2)]


@pytest.mark.asyncio
async def test_impact_flags_a_vulnerability_older_than_retention_as_overdue(client, retained):
    resp = await client.get("/api/v1/analytics/impact", headers=retained)

    assert resp.status_code == 200, resp.text
    lodash = next(row for row in resp.json() if row["component"] == "lodash")
    assert lodash["days_known"] == 200
    assert any(reason.startswith("overdue:") for reason in lodash["priority_reasons"])
