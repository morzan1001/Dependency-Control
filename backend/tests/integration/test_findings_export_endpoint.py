"""End-to-end tests for the rebuilt multi-branch findings CSV export."""

import csv
import io
from datetime import datetime, timedelta, timezone

import pytest

_NOW = datetime(2026, 8, 10, 12, 0, tzinfo=timezone.utc)
_PID = "test-project-id"


async def _seed_scan(db, scan_id, branch, *, status="completed", age_hours=0):
    await db.scans.insert_one(
        {
            "_id": scan_id,
            "project_id": _PID,
            "branch": branch,
            "status": status,
            "created_at": _NOW - timedelta(hours=age_hours),
            "commit_hash": f"c-{scan_id}",
        }
    )


async def _seed_finding(db, scan_id, *, finding_id, ftype="vulnerability", severity="HIGH", **extra):
    doc = {
        "project_id": _PID,
        "scan_id": scan_id,
        "finding_id": finding_id,
        "type": ftype,
        "severity": severity,
        "component": extra.pop("component", "lodash"),
        "version": extra.pop("version", "4.17.20"),
        "description": extra.pop("description", f"desc {finding_id}"),
        "scanners": ["grype"],
        "details": extra.pop("details", {}),
        "waived": extra.pop("waived", False),
        **extra,
    }
    await db.findings.insert_one(doc)


def _parse(resp) -> list[dict]:
    assert resp.headers["content-type"].startswith("text/csv")
    text = resp.text
    assert text.startswith("﻿")
    return list(csv.DictReader(io.StringIO(text.lstrip("﻿"))))


@pytest.mark.asyncio
async def test_export_covers_latest_scan_of_each_active_branch(client, db, member_auth_headers):
    await _seed_scan(db, "s-main-old", "main", age_hours=5)
    await _seed_scan(db, "s-main", "main")
    await _seed_scan(db, "s-dev", "dev")
    await _seed_scan(db, "s-pending", "feat", status="processing")  # branch skipped: no completed scan
    await _seed_finding(db, "s-main-old", finding_id="CVE-OLD")
    await _seed_finding(
        db,
        "s-main",
        finding_id="CVE-1",
        details={"epss_score": 0.97, "in_kev": True, "fixed_version": "4.17.21"},
    )
    await _seed_finding(db, "s-dev", finding_id="CVE-2", severity="CRITICAL")

    resp = await client.get(f"/api/v1/projects/{_PID}/export/csv", headers=member_auth_headers)

    assert resp.status_code == 200
    rows = _parse(resp)
    assert {(r["branch"], r["finding_id"]) for r in rows} == {("main", "CVE-1"), ("dev", "CVE-2")}
    kev_row = next(r for r in rows if r["finding_id"] == "CVE-1")
    assert kev_row["kev"] == "true"
    assert kev_row["epss_score"] == "0.97"
    assert kev_row["commit"] == "c-s-main"
    assert kev_row["fixed_version"] == "4.17.21"


@pytest.mark.asyncio
async def test_rows_sorted_by_severity_within_branch(client, db, member_auth_headers):
    await _seed_scan(db, "s1", "main")
    await _seed_finding(db, "s1", finding_id="LOW-1", severity="LOW")
    await _seed_finding(db, "s1", finding_id="CRIT-1", severity="CRITICAL")
    await _seed_finding(db, "s1", finding_id="MED-1", severity="MEDIUM")

    rows = _parse(await client.get(f"/api/v1/projects/{_PID}/export/csv", headers=member_auth_headers))

    assert [r["finding_id"] for r in rows] == ["CRIT-1", "MED-1", "LOW-1"]


@pytest.mark.asyncio
async def test_license_and_waived_columns(client, db, member_auth_headers):
    await _seed_scan(db, "s1", "main")
    await _seed_finding(
        db,
        "s1",
        finding_id="LIC-GPL",
        ftype="license",
        severity="MEDIUM",
        details={"license": "GPL-3.0-only", "category": "strong_copyleft"},
        waived=True,
        waiver_reason="approved by legal",
    )

    row = _parse(await client.get(f"/api/v1/projects/{_PID}/export/csv", headers=member_auth_headers))[0]

    assert row["license"] == "GPL-3.0-only"
    assert row["license_category"] == "strong_copyleft"
    assert row["waived"] == "true"
    assert row["waiver_reason"] == "approved by legal"
    assert row["kev"] == ""  # enrichment columns stay empty for non-vulnerability rows


@pytest.mark.asyncio
async def test_404_when_no_branch_has_a_completed_scan(client, db, member_auth_headers):
    await _seed_scan(db, "s1", "main", status="processing")
    resp = await client.get(f"/api/v1/projects/{_PID}/export/csv", headers=member_auth_headers)
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_export_includes_every_finding_type(client, db, member_auth_headers):
    """No type filter: a non-vulnerability finding must still appear in the export."""
    await _seed_scan(db, "s1", "main")
    await _seed_finding(db, "s1", finding_id="CVE-1")
    await _seed_finding(
        db,
        "s1",
        finding_id="SECRET-1",
        ftype="secret",
        severity="HIGH",
        component="config.yaml",
        version="",
    )

    rows = _parse(await client.get(f"/api/v1/projects/{_PID}/export/csv", headers=member_auth_headers))

    assert {r["finding_id"] for r in rows} == {"CVE-1", "SECRET-1"}
    secret_row = next(r for r in rows if r["finding_id"] == "SECRET-1")
    assert secret_row["purl"] == ""
    assert secret_row["direct"] == ""


@pytest.mark.asyncio
async def test_purl_and_direct_are_joined_from_dependencies(client, db, member_auth_headers):
    await _seed_scan(db, "s1", "main")
    await db.dependencies.insert_one(
        {
            "project_id": _PID,
            "scan_id": "s1",
            "name": "lodash",
            "version": "4.17.20",
            "purl": "pkg:npm/lodash@4.17.20",
            "direct": True,
        }
    )
    await _seed_finding(db, "s1", finding_id="CVE-1")

    row = _parse(await client.get(f"/api/v1/projects/{_PID}/export/csv", headers=member_auth_headers))[0]

    assert row["purl"] == "pkg:npm/lodash@4.17.20"
    assert row["direct"] == "true"


@pytest.mark.asyncio
async def test_reachable_column_reads_is_reachable_flag(client, db, member_auth_headers):
    await _seed_scan(db, "s1", "main")
    await _seed_finding(db, "s1", finding_id="CVE-1", details={"reachability": {"is_reachable": True}})

    row = _parse(await client.get(f"/api/v1/projects/{_PID}/export/csv", headers=member_auth_headers))[0]

    assert row["reachable"] == "true"
