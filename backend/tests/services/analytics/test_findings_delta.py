from datetime import datetime, timezone

import pytest

from app.services.analytics.findings_delta import (
    _FETCH_PROJECTION,
    compute_findings_delta,
    finding_identity_key,
)


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


def test_identity_key_sast_uses_sast_finding_ids():
    """Merged SAST details carry the rule ids in sast_findings[].id, never a top-level rule_id."""
    f = {
        "type": "sast",
        "component": "src/api/keys.py",
        "details": {
            "sast_findings": [{"id": "py/tainted-query"}, {"id": "py/sql-injection"}],
            "file": "src/api/keys.py",
            "line": 42,
            "cwe_ids": [],
            "category_groups": [],
            "owasp": [],
        },
    }
    assert finding_identity_key(f) == ("sast", "src/api/keys.py", "py/sql-injection,py/tainted-query:42")


def test_identity_key_sast_distinguishes_rules_on_same_line():
    base = {
        "type": "sast",
        "component": "src/api/keys.py",
        "details": {"sast_findings": [{"id": "rule-a"}], "file": "src/api/keys.py", "line": 42},
    }
    other = {
        "type": "sast",
        "component": "src/api/keys.py",
        "details": {"sast_findings": [{"id": "rule-b"}], "file": "src/api/keys.py", "line": 42},
    }
    assert finding_identity_key(base) != finding_identity_key(other)


def test_identity_key_iac_uses_rule_id():
    """KICS normalizer stores the check id as details.rule_id."""
    f = {
        "type": "iac",
        "component": "deploy/main.tf",
        "details": {"rule_id": "aws-s3-public", "title": "Public bucket"},
    }
    assert finding_identity_key(f) == ("iac", "deploy/main.tf", "aws-s3-public")


def test_identity_key_license_uses_license():
    """License findings carry the SPDX id in details.license; license_id is never written."""
    f = {
        "type": "license",
        "component": "lodash@4.17.21",
        "details": {"license": "GPL-3.0-only", "category": "strong_copyleft"},
    }
    assert finding_identity_key(f) == ("license", "lodash@4.17.21", "GPL-3.0-only")


def test_identity_key_eol_uses_eol_date_only():
    """EolDetails declares no `version` and the EOL writer never writes one: 0 of 5,669
    production EOL findings carry details.version, all 5,669 carry eol_date. The extra
    fallback key was invisible to the drift guard because it travels through *keys."""
    f = {
        "type": "eol",
        "component": "python",
        "version": "3.4.10",
        "details": {"fixed_version": "3.4.13", "eol_date": "2025-12-31", "cycle": "3.4", "link": None, "lts": False},
    }
    assert finding_identity_key(f) == ("eol", "python", "2025-12-31")


def test_identity_key_eol_without_a_date_falls_back_to_the_fingerprint():
    f = {"type": "eol", "component": "python", "version": "3.4.10", "description": "EOL", "details": {"cycle": "3.4"}}
    assert finding_identity_key(f)[2] != "3.4.10"


def test_identity_key_malware_typosquat_uses_imitated_package():
    f = {
        "type": "malware",
        "component": "axios2",
        "details": {"imitated_package": "axios", "similarity": 0.92},
    }
    assert finding_identity_key(f) == ("malware", "axios2", "axios")


def test_identity_key_malware_os_malware_uses_info_id():
    f = {
        "type": "malware",
        "component": "evil-pkg",
        "details": {
            "info": {"id": "MAL-2023-1234", "description": "bad"},
            "threats": ["trojan"],
            "reference": "https://example.com/mal",
            "source": "opensourcemalware",
        },
    }
    assert finding_identity_key(f) == ("malware", "evil-pkg", "MAL-2023-1234")


def test_identity_key_malware_os_malware_falls_back_to_reference():
    f = {
        "type": "malware",
        "component": "evil-pkg",
        "details": {
            "info": {"description": "bad"},
            "threats": [],
            "reference": "https://example.com/mal",
            "source": "opensourcemalware",
        },
    }
    assert finding_identity_key(f) == ("malware", "evil-pkg", "https://example.com/mal")


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


def _agg_vuln_doc(_id, scan_id, component, version, cve_ids, severity="CRITICAL", description=""):
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
        "description": description,
        "details": {
            "vulnerabilities": [{"id": c, "description": f"desc {c}"} for c in cve_ids],
            "fixed_version": None,
        },
        "scan_created_at": datetime.now(timezone.utc),
    }


def _secret_doc(_id, scan_id, description="leaked"):
    return {
        "_id": _id,
        "project_id": "p1",
        "scan_id": scan_id,
        "finding_id": "SECRET-AWS-abcd1234",
        "type": "secret",
        "severity": "HIGH",
        "component": "src/x.py",
        "description": description,
        "details": {"detector": "AWS", "verified": True},
        "scan_created_at": datetime.now(timezone.utc),
    }


async def _seed_added_removed(db):
    await db["findings"].insert_many(
        [
            _agg_vuln_doc("fa1", "sa", "lib", "1", ["CVE-A"], description="CVE-A"),
            _secret_doc("fa2", "sa"),
            _agg_vuln_doc("fb1", "sb", "lib", "1", ["CVE-A"], description="CVE-A again"),
            _agg_vuln_doc("fb2", "sb", "other", "2", ["CVE-NEW"], severity="MEDIUM"),
        ]
    )


@pytest.mark.asyncio
async def test_findings_delta_added_and_removed(db):
    await _seed_added_removed(db)

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
    assert added[0].first_seen is not None
    assert len(removed) == 1 and removed[0].finding_type == "secret"


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
            _agg_vuln_doc("x1", "sb", "c", "1", ["C1"], severity="CRITICAL"),
            _agg_vuln_doc("x2", "sb", "c", "2", ["C2"], severity="LOW"),
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
    docs = [_agg_vuln_doc(f"y{i}", "sb", "c", str(i), [f"CVE-{i}"], severity="LOW") for i in range(120)]
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


def _sast_doc(_id, scan_id, rule_ids, line=42):
    return {
        "_id": _id,
        "project_id": "p1",
        "scan_id": scan_id,
        "finding_id": _id,
        "type": "sast",
        "severity": "HIGH",
        "component": "src/api/keys.py",
        "description": "injection",
        "details": {
            "sast_findings": [{"id": r} for r in rule_ids],
            "file": "src/api/keys.py",
            "line": line,
            "cwe_ids": [],
            "category_groups": [],
            "owasp": [],
        },
        "scan_created_at": datetime.now(timezone.utc),
    }


@pytest.mark.asyncio
async def test_sast_rule_swap_on_same_line_is_added_and_removed(db):
    """Swapping rule A for rule B on the same file/line must not read as unchanged."""
    await db["findings"].insert_many(
        [
            _sast_doc("sa1", "sa", ["rule-a"]),
            _sast_doc("sb1", "sb", ["rule-b"]),
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
async def test_malware_similarity_text_change_stays_unchanged(db):
    """A typosquat whose similarity/description changes keeps its identity via imitated_package."""
    base = {
        "project_id": "p1",
        "finding_id": "TYPO-axios2",
        "type": "malware",
        "severity": "CRITICAL",
        "component": "axios2",
        "scan_created_at": datetime.now(timezone.utc),
    }
    await db["findings"].insert_many(
        [
            {
                **base,
                "_id": "m_a",
                "scan_id": "sa",
                "description": "'axios2' is 92% similar to 'axios'",
                "details": {"imitated_package": "axios", "similarity": 0.92},
            },
            {
                **base,
                "_id": "m_b",
                "scan_id": "sb",
                "description": "'axios2' is 95% similar to 'axios'",
                "details": {"imitated_package": "axios", "similarity": 0.95},
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
async def test_secret_identity_stable_across_scans_by_finding_id(db):
    """Same finding_id in both scans stays unchanged even though per-scan _id differs and details carry no hash."""
    await db["findings"].insert_many(
        [
            _secret_doc("s_a", "sa", description="Secret detected: AWS"),
            _secret_doc("s_b", "sb", description="Secret detected: AWS"),
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
        "scan_created_at",
        "details.vulnerabilities.id",
        "details.fixed_version",
        "details.sast_findings.id",
        "details.imitated_package",
        "details.info.id",
        "details.reference",
        "details.license",
    ):
        assert proj.get(field) == 1
    # Keys no writer ever emits must not be fetched.
    for gone in (
        "created_at",
        "details.cve_id",
        "details.vuln_id",
        "details.license_id",
        "details.signature",
    ):
        assert gone not in proj


def test_identity_key_vulnerability_survives_a_component_requalification():
    """The same package reported bare and group-qualified must not read as removed + added."""
    bare = {
        "type": "vulnerability",
        "component": "jackson-databind",
        "version": "2.20.2",
        "description": "",
        "details": {"vulnerabilities": [{"id": "CVE-2026-1"}]},
    }
    qualified = {**bare, "component": "com.fasterxml.jackson.core:jackson-databind"}

    assert finding_identity_key(bare) == finding_identity_key(qualified)


def test_identity_key_keeps_same_named_files_in_different_directories_apart():
    """Only package components are folded; SAST/secret components are file paths."""
    a = {"type": "secret", "component": "src/a/util.js", "finding_id": "SECRET-1", "details": {}}
    b = {"type": "secret", "component": "src/b/util.js", "finding_id": "SECRET-1", "details": {}}

    assert finding_identity_key(a) != finding_identity_key(b)
