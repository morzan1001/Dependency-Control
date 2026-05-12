from datetime import datetime, timezone

import pytest

from app.services.analytics.findings_delta import (
    compute_findings_delta,
    finding_identity_key,
)


def test_identity_key_vulnerability_uses_cve_id():
    f = {
        "type": "vulnerability",
        "component": "log4j-core@2.17.1",
        "details": {"cve_id": "CVE-2025-1234"},
    }
    assert finding_identity_key(f) == ("vulnerability", "log4j-core@2.17.1", "CVE-2025-1234")


def test_identity_key_secret_uses_pattern_hash():
    f = {
        "type": "secret",
        "component": "src/api/keys.py",
        "details": {"pattern_hash": "abc123"},
    }
    assert finding_identity_key(f) == ("secret", "src/api/keys.py", "abc123")


def test_identity_key_sast_uses_rule_id():
    f = {
        "type": "sast",
        "component": "src/api/keys.py",
        "details": {"rule_id": "py/sql-injection", "line": 42},
    }
    assert finding_identity_key(f) == ("sast", "src/api/keys.py", "py/sql-injection:42")


def test_identity_key_license_uses_license_id():
    f = {
        "type": "license",
        "component": "lodash@4.17.21",
        "details": {"license_id": "GPL-3.0"},
    }
    assert finding_identity_key(f) == ("license", "lodash@4.17.21", "GPL-3.0")


def test_identity_key_unknown_falls_back_to_full_fingerprint():
    f = {
        "type": "other",
        "component": "x",
        "details": {},
        "description": "weird thing",
    }
    key = finding_identity_key(f)
    assert key[0] == "other"
    assert key[1] == "x"
    assert key[2] != ""  # some fallback identifier present


@pytest.mark.asyncio
async def test_findings_delta_added_and_removed(db):
    await db["findings"].insert_many(
        [
            {
                "_id": "fa1",
                "project_id": "p1",
                "scan_id": "sa",
                "finding_id": "fa1",
                "type": "vulnerability",
                "severity": "critical",
                "component": "lib@1",
                "description": "CVE-A",
                "details": {"cve_id": "CVE-A"},
                "created_at": datetime.now(timezone.utc),
            },
            {
                "_id": "fa2",
                "project_id": "p1",
                "scan_id": "sa",
                "finding_id": "fa2",
                "type": "secret",
                "severity": "high",
                "component": "src/x.py",
                "description": "leaked",
                "details": {"pattern_hash": "h1"},
                "created_at": datetime.now(timezone.utc),
            },
            {
                "_id": "fb1",
                "project_id": "p1",
                "scan_id": "sb",
                "finding_id": "fb1",
                "type": "vulnerability",
                "severity": "critical",
                "component": "lib@1",
                "description": "CVE-A again",
                "details": {"cve_id": "CVE-A"},
                "created_at": datetime.now(timezone.utc),
            },
            {
                "_id": "fb2",
                "project_id": "p1",
                "scan_id": "sb",
                "finding_id": "fb2",
                "type": "vulnerability",
                "severity": "medium",
                "component": "other@2",
                "description": "CVE-NEW",
                "details": {"cve_id": "CVE-NEW"},
                "created_at": datetime.now(timezone.utc),
            },
        ]
    )

    resp = await compute_findings_delta(
        db,
        project_id="p1",
        from_scan="sa",
        to_scan="sb",
        page=1,
        page_size=50,
        change=None,
        severity=None,
        finding_type=None,
    )

    assert resp.totals.added == 1
    assert resp.totals.removed == 1
    assert resp.totals.unchanged == 1
    assert resp.totals.by_severity["medium"] == 1  # added
    assert resp.totals.by_type["vulnerability"] == 1
    added = [i for i in resp.items if i.change == "added"]
    removed = [i for i in resp.items if i.change == "removed"]
    assert len(added) == 1 and added[0].cve_id == "CVE-NEW"
    assert len(removed) == 1 and removed[0].finding_type == "secret"


@pytest.mark.asyncio
async def test_findings_delta_severity_filter(db):
    await db["findings"].insert_many(
        [
            {
                "_id": "x1",
                "project_id": "p1",
                "scan_id": "sb",
                "type": "vulnerability",
                "severity": "critical",
                "component": "c",
                "description": "d",
                "details": {"cve_id": "C1"},
                "created_at": datetime.now(timezone.utc),
            },
            {
                "_id": "x2",
                "project_id": "p1",
                "scan_id": "sb",
                "type": "vulnerability",
                "severity": "low",
                "component": "c",
                "description": "d",
                "details": {"cve_id": "C2"},
                "created_at": datetime.now(timezone.utc),
            },
        ]
    )
    resp = await compute_findings_delta(
        db,
        project_id="p1",
        from_scan="sa",
        to_scan="sb",
        page=1,
        page_size=50,
        change=None,
        severity=["critical"],
        finding_type=None,
    )
    assert resp.totals.added == 1
    assert resp.items[0].severity == "critical"


@pytest.mark.asyncio
async def test_findings_delta_pagination(db):
    docs = [
        {
            "_id": f"y{i}",
            "project_id": "p1",
            "scan_id": "sb",
            "type": "vulnerability",
            "severity": "low",
            "component": "c",
            "description": "d",
            "details": {"cve_id": f"CVE-{i}"},
            "created_at": datetime.now(timezone.utc),
        }
        for i in range(120)
    ]
    await db["findings"].insert_many(docs)
    resp = await compute_findings_delta(
        db,
        project_id="p1",
        from_scan="sa",
        to_scan="sb",
        page=2,
        page_size=50,
        change=None,
        severity=None,
        finding_type=None,
    )
    assert resp.totals.added == 120
    assert resp.page == 2
    assert resp.page_size == 50
    assert resp.total_pages == 3
    assert len(resp.items) == 50
