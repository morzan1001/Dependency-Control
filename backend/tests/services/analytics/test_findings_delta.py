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


def test_identity_key_outdated_follows_the_project_not_the_upstream_release():
    """details.fixed_version is the registry's latest release, which moves while the project stands still."""
    behind = {
        "type": "outdated",
        "component": "requests",
        "finding_id": "OUTDATED-requests",
        "details": {"fixed_version": "2.32.0"},
    }
    released = {**behind, "details": {"fixed_version": "2.33.0"}}
    ahead = {**behind, "finding_id": "OUTDATED-requests-ahead", "details": {"ahead_of_default": True}}

    assert (
        finding_identity_key(behind) == finding_identity_key(released) == ("outdated", "requests", "OUTDATED-requests")
    )
    assert finding_identity_key(ahead) != finding_identity_key(behind)


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
    assert finding_identity_key(f) == ("sast", "src/api/keys.py", "py/sql-injection,py/tainted-query")


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


def test_identity_key_iac_keys_on_the_rule_and_search_key():
    """KICS hashes the line into similarity_id for searchLine queries; search_key names the resource without it."""
    f = {
        "type": "iac",
        "component": "main.tf",
        "details": {
            "rule_id": "f861041c",
            "start": {"line": 5},
            "similarity_id": "dd089a52",
            "search_key": "aws_s3_bucket[assets]",
        },
    }
    keyless = {**f, "details": {"rule_id": "f861041c", "start": {"line": 5}}}

    assert finding_identity_key(f) == ("iac", "main.tf", "f861041c:aws_s3_bucket[assets]")
    assert finding_identity_key(keyless) == ("iac", "main.tf", "f861041c:5")


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


def test_identity_key_malware_prefers_the_osv_id_over_the_owning_feed_s_reference():
    f = {
        "type": "malware",
        "component": "evil-pkg",
        "details": {
            "osv_id": "MAL-2023-1234",
            "info": {"description": "bad"},
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


def test_identity_key_quality_is_version_free():
    """The aggregated finding_id is QUALITY:<component>:<version>; the issue ids name only the component."""
    f = {
        "type": "quality",
        "component": "left-pad",
        "version": "1.3.0",
        "finding_id": "QUALITY:left-pad:1.3.0",
        "description": "No releases in 400 days",
        "details": {"quality_issues": [{"id": "SCORECARD-left-pad"}, {"id": "MAINT-left-pad"}]},
    }
    bumped = {**f, "version": "1.3.1", "finding_id": "QUALITY:left-pad:1.3.1", "description": "No releases in 401 days"}

    assert (
        finding_identity_key(f)
        == finding_identity_key(bumped)
        == ("quality", "left-pad", "MAINT-left-pad,SCORECARD-left-pad")
    )


def test_identity_key_crypto_drops_the_per_scan_bom_ref():
    f = {
        "type": "crypto_weak_algorithm",
        "component": "MD5 [bom-ref:crypto/md5-1]",
        "details": {"rule_id": "md5", "bom_ref": "crypto/md5-1"},
    }

    assert finding_identity_key(f) == ("crypto_weak_algorithm", "MD5", "md5")


def test_identity_key_system_warning_keys_on_its_text():
    f = {"type": "system_warning", "component": "scanner", "description": "trivy timed out", "details": {}}
    other = {**f, "description": "grype timed out"}

    assert finding_identity_key(f) != finding_identity_key(other)


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
        "first_seen_at": datetime.now(timezone.utc),
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
        "first_seen_at": datetime.now(timezone.utc),
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
    assert resp.totals.by_severity["MEDIUM"] == 1
    assert resp.totals.by_type["vulnerability"] == 1
    added = [i for i in resp.items if i.change == "added"]
    removed = [i for i in resp.items if i.change == "removed"]
    assert len(added) == 1 and added[0].cve_id == "CVE-NEW"
    assert added[0].first_seen is not None
    assert len(removed) == 1 and removed[0].finding_type == "secret"


@pytest.mark.asyncio
async def test_an_advisory_is_named_by_its_cve_as_on_the_scan_page(db):
    """A GHSA with a CVE alias, or a CVE behind a GHSA-only advisory, is shown under the CVE."""
    aliased = _agg_vuln_doc("fb1", "sb", "lodash", "4.17.20", [])
    aliased["details"]["vulnerabilities"] = [{"id": "GHSA-35jh-r3h4-6jhm", "aliases": ["CVE-2021-23337"]}]
    later = _agg_vuln_doc("fb2", "sb", "minimist", "1.2.0", ["GHSA-vh95-rmgr-6w4m", "CVE-2020-7598"])
    await db["findings"].insert_many([aliased, later])

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

    assert sorted(i.cve_id for i in resp.items) == ["CVE-2020-7598", "CVE-2021-23337"]


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
    assert resp.totals.by_severity.get("MEDIUM") == 1  # added CVE-NEW
    assert resp.totals.by_severity.get("HIGH") == 1  # removed secret
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
    assert resp.items[0].severity == "CRITICAL"


@pytest.mark.asyncio
@pytest.mark.parametrize(("severity", "unchanged"), [(["high"], 1), (["critical"], 1), (["low"], 0)])
async def test_a_rescored_finding_stays_unchanged_under_a_severity_filter(db, severity, unchanged):
    """Severity is not part of the identity, so the filter narrows the result instead of splitting the pair."""
    await db["findings"].insert_many(
        [
            _agg_vuln_doc("r1", "sa", "x", "1", ["CVE-1"], severity="HIGH"),
            _agg_vuln_doc("r2", "sb", "x", "1", ["CVE-1"], severity="CRITICAL"),
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
        severity=severity,
        finding_type=None,
    )
    assert (resp.totals.added, resp.totals.removed, resp.totals.unchanged) == (0, 0, unchanged)
    assert resp.items == []


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
async def test_aggregated_vuln_cve_swap_is_one_changed_record(db):
    """Dropping CVE-A and gaining CVE-B at the same version is a change to the record, not unchanged."""
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
    assert (resp.totals.added, resp.totals.removed, resp.totals.changed, resp.totals.unchanged) == (0, 0, 1, 0)
    [item] = resp.items
    assert (item.change, item.cve_id, item.added_cves, item.dropped_cves) == ("changed", "CVE-B", ["CVE-B"], ["CVE-A"])


@pytest.mark.asyncio
async def test_a_version_bump_that_fixes_nothing_names_no_cve(db):
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
    assert (resp.totals.added, resp.totals.removed, resp.totals.changed, resp.totals.unchanged) == (0, 0, 1, 0)
    [item] = resp.items
    assert (item.from_version, item.to_version, item.cve_id, item.added_cves, item.dropped_cves) == (
        "4.17.20",
        "4.17.21",
        None,
        [],
        [],
    )


@pytest.mark.asyncio
async def test_an_upgrade_that_fixes_one_cve_is_a_change_not_a_new_critical(db):
    await db["findings"].insert_many(
        [
            _agg_vuln_doc("a", "sa", "lodash", "4.17.20", ["CVE-2021-23337", "CVE-2020-8203"]),
            _agg_vuln_doc("b", "sb", "lodash", "4.17.21", ["CVE-2021-23337"]),
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
    assert (resp.totals.added, resp.totals.removed, resp.totals.changed) == (0, 0, 1)
    assert resp.totals.by_severity == {}
    [item] = resp.items
    assert (item.cve_id, item.added_cves, item.dropped_cves) == ("CVE-2020-8203", [], ["CVE-2020-8203"])


@pytest.mark.asyncio
async def test_a_changed_record_reports_the_earlier_first_detection(db):
    first = datetime(2026, 1, 5, tzinfo=timezone.utc)
    before = _agg_vuln_doc("a", "sa", "lodash", "4.17.20", ["CVE-A"]) | {"first_seen_at": first}
    after = _agg_vuln_doc("b", "sb", "lodash", "4.17.21", ["CVE-A"])
    await db["findings"].insert_many([before, after])

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

    assert resp.items[0].first_seen == first


@pytest.mark.asyncio
async def test_two_versions_leaving_one_behind_are_not_paired_into_a_change(db):
    await db["findings"].insert_many(
        [
            _agg_vuln_doc("a1", "sa", "lodash", "4.17.19", ["CVE-A"]),
            _agg_vuln_doc("a2", "sa", "lodash", "4.17.20", ["CVE-A"]),
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
    assert (resp.totals.added, resp.totals.removed, resp.totals.changed) == (1, 2, 0)


@pytest.mark.asyncio
async def test_the_change_filter_selects_changed_records(db):
    await db["findings"].insert_many(
        [
            _agg_vuln_doc("a", "sa", "lodash", "4.17.20", ["CVE-A"]),
            _agg_vuln_doc("b", "sb", "lodash", "4.17.21", ["CVE-A"]),
            _agg_vuln_doc("c", "sb", "minimist", "1.2.0", ["CVE-B"]),
        ]
    )
    resp = await compute_findings_delta(
        db,
        project_id="p1",
        from_scan="sa",
        to_scan="sb",
        page=1,
        page_size=50,
        change="changed",
        severity=None,
        finding_type=None,
    )
    assert [i.change for i in resp.items] == ["changed"]
    assert (resp.totals.added, resp.totals.changed) == (1, 1)


def _license_doc(_id, scan_id, version):
    return {
        "_id": _id,
        "project_id": "p1",
        "scan_id": scan_id,
        "finding_id": "LIC-GPL-3.0-only",
        "type": "license",
        "severity": "HIGH",
        "component": "foo",
        "version": version,
        "description": "GPL-3.0-only",
        "details": {"license": "GPL-3.0-only"},
    }


async def _license_delta(db, from_versions, to_versions):
    await db["findings"].insert_many(
        [_license_doc(f"a{v}", "sa", v) for v in from_versions] + [_license_doc(f"b{v}", "sb", v) for v in to_versions]
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
    return resp.totals.added, resp.totals.removed, resp.totals.unchanged


@pytest.mark.asyncio
async def test_a_second_version_with_the_same_license_is_added(db):
    assert await _license_delta(db, ["1.0"], ["1.0", "2.0"]) == (1, 0, 1)


@pytest.mark.asyncio
async def test_dropping_one_of_two_versions_with_the_same_license_is_removed(db):
    assert await _license_delta(db, ["1.0", "2.0"], ["2.0"]) == (0, 1, 1)


@pytest.mark.asyncio
async def test_upgrading_the_only_version_leaves_the_license_finding_unchanged(db):
    assert await _license_delta(db, ["1.0"], ["2.0"]) == (0, 0, 1)


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
        "first_seen_at": datetime.now(timezone.utc),
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
        "first_seen_at": datetime.now(timezone.utc),
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
        "first_seen_at",
        "details.vulnerabilities.id",
        "details.sast_findings.id",
        "details.imitated_package",
        "details.osv_id",
        "details.reference",
        "details.license",
    ):
        assert proj.get(field) == 1
    # Keys the delta does not read must not be fetched.
    for gone in (
        "created_at",
        "scan_created_at",
        "details.fixed_version",
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
