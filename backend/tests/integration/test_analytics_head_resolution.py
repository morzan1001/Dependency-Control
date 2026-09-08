"""Every head-resolving analytics surface must name the same build.

The project here is the unambiguous case: default branch scanned, nothing deleted, a long-lived
release, a rescan the rescanner just produced of it, and the branch tip carrying a CRITICAL that
exists nowhere else.
"""

from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio

_NOW = datetime(2026, 9, 4, 12, 0, tzinfo=timezone.utc)
_PROJECT = "p"
_RELEASE_SCAN = "scan-release"
_TIP_SCAN = "scan-tip"
_RESCAN = "scan-rescan-of-release"
_RELEASE_AGE_DAYS = 200
_TIP_AGE_DAYS = 2
_TIP_ONLY_COMPONENT = "tip-only-lib"
_RELEASE_COMPONENT = "legacy-lib"
_TIP_ONLY_CVE = "CVE-2026-99999"


def _scan(scan_id: str, days_old: int, **extra) -> dict:
    doc = {
        "_id": scan_id,
        "project_id": _PROJECT,
        "branch": "main",
        "status": "completed",
        "created_at": _NOW - timedelta(days=days_old),
    }
    doc.update(extra)
    return doc


def _vulnerability(scan_id: str, cve: str, severity: str, component: str) -> dict:
    return {
        "_id": f"{scan_id}:{cve}",
        "id": cve,
        "finding_id": cve,
        "scan_id": scan_id,
        "project_id": _PROJECT,
        "type": "vulnerability",
        "severity": severity,
        "component": component,
        "version": "1.0.0",
        "description": "",
        "scanners": ["trivy"],
        "waived": False,
        "details": {"vulnerabilities": [{"id": cve, "severity": severity, "aliases": []}]},
    }


def _dependency(scan_id: str, name: str) -> dict:
    return {
        "_id": f"{scan_id}:{name}",
        "scan_id": scan_id,
        "project_id": _PROJECT,
        "name": name,
        "version": "1.0.0",
        "purl": f"pkg:pypi/{name}@1.0.0",
        "type": "pypi",
        "direct": True,
        "parent_components": [],
    }


@pytest_asyncio.fixture
async def seeded(db, owner_auth_headers_proj):
    await db.scans.insert_many(
        [
            _scan(_RELEASE_SCAN, _RELEASE_AGE_DAYS, is_release=True),
            _scan(_TIP_SCAN, _TIP_AGE_DAYS),
            _scan(_RESCAN, 0, is_rescan=True, original_scan_id=_RELEASE_SCAN),
        ]
    )
    await db.projects.update_one(
        {"_id": _PROJECT},
        {"$set": {"default_branch": "main", "deleted_branches": [], "latest_scan_id": _TIP_SCAN}},
    )
    await db.findings.insert_many(
        [
            _vulnerability(_RELEASE_SCAN, "CVE-2020-11111", "HIGH", _RELEASE_COMPONENT),
            _vulnerability(_RESCAN, "CVE-2020-11111", "HIGH", _RELEASE_COMPONENT),
            _vulnerability(_TIP_SCAN, _TIP_ONLY_CVE, "CRITICAL", _TIP_ONLY_COMPONENT),
        ]
    )
    await db.dependencies.insert_many(
        [
            _dependency(_RELEASE_SCAN, _RELEASE_COMPONENT),
            _dependency(_RESCAN, _RELEASE_COMPONENT),
            _dependency(_TIP_SCAN, _TIP_ONLY_COMPONENT),
        ]
    )
    return owner_auth_headers_proj


@pytest.mark.asyncio
async def test_recommendations_run_on_the_branch_tip_not_the_freshest_rescan(client, seeded):
    resp = await client.get(f"/api/v1/analytics/projects/{_PROJECT}/recommendations", headers=seeded)

    assert resp.status_code == 200, resp.text
    assert resp.json()["scan_id"] == _TIP_SCAN


@pytest.mark.asyncio
async def test_recommendations_see_a_critical_that_only_the_tip_reports(client, seeded):
    resp = await client.get(f"/api/v1/analytics/projects/{_PROJECT}/recommendations", headers=seeded)

    assert resp.status_code == 200, resp.text
    assert _TIP_ONLY_CVE in resp.text


@pytest.mark.asyncio
async def test_the_dependency_tree_shows_the_tips_graph_when_a_branch_was_deleted(client, db, seeded):
    """Any deleted branch used to send the Tree tab down its own resolver, which ranked the
    rescan of the release above the tip while every other tab stayed on the tip."""
    await db.projects.update_one({"_id": _PROJECT}, {"$set": {"deleted_branches": ["feature/old"]}})

    resp = await client.get(f"/api/v1/analytics/projects/{_PROJECT}/dependency-tree", headers=seeded)

    assert resp.status_code == 200, resp.text
    assert [node["name"] for node in resp.json()["nodes"]] == [_TIP_ONLY_COMPONENT]


_QUEUED_SCAN = "scan-queued"
_LICENSE_DRIFT = "license_drift"
_DRIFTING_COMPONENT = "legacy-lib"
_PERMISSIVE_LICENSE = "MIT"
_COPYLEFT_LICENSE = "GPL-3.0-only"


def _license_finding(scan_id: str, licence: str, category: str) -> dict:
    return {
        "_id": f"{scan_id}:license",
        "id": f"LIC-{licence}",
        "finding_id": f"LIC-{licence}",
        "scan_id": scan_id,
        "project_id": _PROJECT,
        "type": "license",
        "severity": "MEDIUM",
        "component": _DRIFTING_COMPONENT,
        "version": "1.0.0",
        "description": "",
        "scanners": ["licensecheck"],
        "waived": False,
        "details": {"license": licence, "category": category},
    }


@pytest_asyncio.fixture
async def licence_drifted_under_a_queued_run(db, seeded):
    """The component's licence turned copyleft between the release and the tip, and CI has since
    enqueued a run that has analysed nothing."""
    await db.scans.insert_one(_scan(_QUEUED_SCAN, 0, status="pending"))
    await db.findings.insert_many(
        [
            _license_finding(_RELEASE_SCAN, _PERMISSIVE_LICENSE, "permissive"),
            _license_finding(_TIP_SCAN, _COPYLEFT_LICENSE, "strong_copyleft"),
        ]
    )
    return seeded


@pytest.mark.asyncio
async def test_recommendations_compare_against_the_preceding_build_not_a_queued_run(
    client, licence_drifted_under_a_queued_run
):
    """A queued run has no findings to compare against, and the licence regression then goes unsaid."""
    resp = await client.get(
        f"/api/v1/analytics/projects/{_PROJECT}/recommendations", headers=licence_drifted_under_a_queued_run
    )

    assert resp.status_code == 200, resp.text
    drift = [r for r in resp.json()["recommendations"] if r["type"] == _LICENSE_DRIFT]
    assert [d["impact"]["total"] for d in drift] == [1]
