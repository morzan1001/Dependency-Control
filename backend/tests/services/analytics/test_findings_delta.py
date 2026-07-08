from datetime import datetime, timezone

import pytest

from app.services.analytics.findings_delta import (
    _FETCH_PROJECTION,
    compute_findings_delta,
    finding_identity_key,
)


def test_identity_key_vulnerability_uses_cve_id():
    # Flat shape supported via fallback.
    f = {
        "type": "vulnerability",
        "component": "log4j-core@2.17.1",
        "details": {"cve_id": "CVE-2025-1234"},
    }
    assert finding_identity_key(f) == ("vulnerability", "log4j-core@2.17.1", "CVE-2025-1234")


def test_identity_key_vulnerability_uses_aggregated_shape():
    """Aggregated shape: ids live under details.vulnerabilities[].id and version is top-level; key is the sorted id set plus version."""
    f = {
        "type": "vulnerability",
        "component": "lodash",
        "version": "4.17.20",
        "description": "",
        "details": {
            "vulnerabilities": [
                {"id": "CVE-B", "description": "b"},
                {"id": "CVE-A", "description": "a"},
            ],
            "fixed_version": "4.17.21",
        },
    }
    assert finding_identity_key(f) == ("vulnerability", "lodash", "4.17.20|CVE-A,CVE-B")


def test_identity_key_secret_uses_finding_id():
    """Secret findings carry no pattern_hash/rule_id in details; identity is the deterministic finding_id."""
    f = {
        "type": "secret",
        "component": "src/api/keys.py",
        "finding_id": "SECRET-AWS-abcd1234",
        "details": {"detector": "AWS", "verified": True},
    }
    assert finding_identity_key(f) == ("secret", "src/api/keys.py", "SECRET-AWS-abcd1234")


def test_identity_key_outdated_uses_fixed_version():
    """Outdated findings store the latest version in details.fixed_version, not details.latest_version."""
    f = {
        "type": "outdated",
        "component": "requests",
        "details": {"fixed_version": "2.32.0"},
    }
    assert finding_identity_key(f) == ("outdated", "requests", "2.32.0")


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
                "severity": "CRITICAL",
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
                "severity": "HIGH",
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
                "severity": "CRITICAL",
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
                "severity": "MEDIUM",
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
    assert resp.totals.by_severity["medium"] == 1
    assert resp.totals.by_type["vulnerability"] == 1
    added = [i for i in resp.items if i.change == "added"]
    removed = [i for i in resp.items if i.change == "removed"]
    assert len(added) == 1 and added[0].cve_id == "CVE-NEW"
    assert len(removed) == 1 and removed[0].finding_type == "secret"


async def _seed_added_removed(db):
    await db["findings"].insert_many(
        [
            {
                "_id": "fa1",
                "project_id": "p1",
                "scan_id": "sa",
                "finding_id": "fa1",
                "type": "vulnerability",
                "severity": "CRITICAL",
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
                "severity": "HIGH",
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
                "severity": "CRITICAL",
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
                "severity": "MEDIUM",
                "component": "other@2",
                "description": "CVE-NEW",
                "details": {"cve_id": "CVE-NEW"},
                "created_at": datetime.now(timezone.utc),
            },
        ]
    )


@pytest.mark.asyncio
async def test_breakdowns_decompose_full_totals_under_change_filter(db):
    """by_severity/by_type decompose the full added+removed totals even when the change filter scopes the paginated item list."""
    await _seed_added_removed(db)
    resp = await compute_findings_delta(
        db,
        project_id="p1",
        from_scan="sa",
        to_scan="sb",
        page=1,
        page_size=50,
        change="added",
        severity=None,
        finding_type=None,
    )
    # totals are independent of the change filter: 1 added, 1 removed
    assert resp.totals.added == 1
    assert resp.totals.removed == 1
    # breakdowns reconcile with added + removed (= 2), not just the displayed 'added'
    assert sum(resp.totals.by_severity.values()) == resp.totals.added + resp.totals.removed
    assert resp.totals.by_severity.get("medium") == 1  # added CVE-NEW
    assert resp.totals.by_severity.get("high") == 1  # removed secret
    assert resp.totals.by_type.get("vulnerability") == 1
    assert resp.totals.by_type.get("secret") == 1
    # the paginated items remain scoped to the change filter
    assert resp.items and all(i.change == "added" for i in resp.items)


@pytest.mark.asyncio
async def test_findings_delta_severity_filter(db):
    await db["findings"].insert_many(
        [
            {
                "_id": "x1",
                "project_id": "p1",
                "scan_id": "sb",
                "type": "vulnerability",
                "severity": "CRITICAL",
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
                "severity": "LOW",
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
            "severity": "LOW",
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


def _agg_vuln_doc(_id, scan_id, component, version, cve_ids, severity="CRITICAL"):
    """Build a persisted vulnerability finding in the real AGGREGATED shape."""
    return {
        "_id": _id,
        "project_id": "p1",
        "scan_id": scan_id,
        "finding_id": f"{component}:{version}",
        "type": "vulnerability",
        "severity": severity,
        "component": component,
        "version": version,
        "description": "",
        "details": {
            "vulnerabilities": [{"id": c, "description": f"desc {c}"} for c in cve_ids],
            "fixed_version": None,
        },
        "created_at": datetime.now(timezone.utc),
    }


@pytest.mark.asyncio
async def test_aggregated_vuln_cve_swap_is_added_and_removed(db):
    """Dropping CVE-A and gaining CVE-B at the same version is added=1/removed=1, not unchanged."""
    await db["findings"].insert_many(
        [
            _agg_vuln_doc("a", "sa", "lodash", "4.17.20", ["CVE-A"]),
            _agg_vuln_doc("b", "sb", "lodash", "4.17.20", ["CVE-B"]),
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
    assert resp.totals.unchanged == 0
    added = [i for i in resp.items if i.change == "added"]
    assert added and added[0].cve_id == "CVE-B"


@pytest.mark.asyncio
async def test_aggregated_vuln_version_bump_is_added_and_removed(db):
    await db["findings"].insert_many(
        [
            _agg_vuln_doc("a", "sa", "lodash", "4.17.20", ["CVE-A"]),
            _agg_vuln_doc("b", "sb", "lodash", "4.17.21", ["CVE-A"]),
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
    assert resp.totals.unchanged == 0


@pytest.mark.asyncio
async def test_aggregated_vuln_unchanged_when_cve_set_identical(db):
    await db["findings"].insert_many(
        [
            _agg_vuln_doc("a", "sa", "lodash", "4.17.20", ["CVE-A", "CVE-B"]),
            _agg_vuln_doc("b", "sb", "lodash", "4.17.20", ["CVE-B", "CVE-A"]),
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
    assert resp.totals.added == 0
    assert resp.totals.removed == 0
    assert resp.totals.unchanged == 1


@pytest.mark.asyncio
async def test_secret_identity_stable_across_scans_by_finding_id(db):
    """Same finding_id in both scans stays unchanged even though per-scan _id differs and details carry no hash."""
    await db["findings"].insert_many(
        [
            {
                "_id": "s_a",
                "project_id": "p1",
                "scan_id": "sa",
                "finding_id": "SECRET-AWS-abcd1234",
                "type": "secret",
                "severity": "CRITICAL",
                "component": "src/x.py",
                "description": "Secret detected: AWS",
                "details": {"detector": "AWS", "verified": True},
                "created_at": datetime.now(timezone.utc),
            },
            {
                "_id": "s_b",
                "project_id": "p1",
                "scan_id": "sb",
                "finding_id": "SECRET-AWS-abcd1234",
                "type": "secret",
                "severity": "CRITICAL",
                "component": "src/x.py",
                "description": "Secret detected: AWS",
                "details": {"detector": "AWS", "verified": True},
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
    assert resp.totals.added == 0
    assert resp.totals.removed == 0
    assert resp.totals.unchanged == 1


@pytest.mark.asyncio
async def test_fetch_uses_projection(db, monkeypatch):
    """Fetch must pass a projection covering the read fields rather than pulling full documents."""
    captured = {}
    coll = db["findings"]
    original_find = coll.find

    def spy_find(query=None, projection=None, **kwargs):
        captured["projection"] = projection
        return original_find(query, projection=projection, **kwargs)

    monkeypatch.setattr(coll, "find", spy_find)

    await compute_findings_delta(
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

    proj = captured["projection"]
    assert proj is _FETCH_PROJECTION
    # Fields the identity/item builders read must be present in the projection.
    for field in (
        "type",
        "component",
        "version",
        "severity",
        "description",
        "found_in",
        "finding_id",
        "created_at",
        "details.vulnerabilities.id",
        "details.fixed_version",
    ):
        assert proj.get(field) == 1
