"""Chat/MCP tools answer per advisory, never pairing a CVE with a sibling advisory's KEV, EPSS or fix."""

from datetime import datetime, timezone

import pytest

from app.core.constants import SCAN_STATUS_COMPLETED
from app.models.user import User
from app.services.aggregation.versions import aggregate_fixed_version
from app.services.chat.tools import ChatToolRegistry
from tests.helpers.permission_presets import PRESET_ADMIN

# The value is unread: the marker on the second case makes the ``db`` fixture hand out a real server.
_DATABASES = [
    pytest.param("attrappe", id="attrappe"),
    pytest.param("real-mongo", marks=pytest.mark.live_mongo, id="real-mongo"),
]

pytestmark = [pytest.mark.asyncio, pytest.mark.parametrize("database", _DATABASES)]

_PROJECT = "p-advisory"
_SCAN = "s-head"
_LOG4SHELL = "CVE-2021-44228"
_LOG4J_DOS = "CVE-2021-45105"
_GHSA = "GHSA-jfh8-c2jp-5v3q"


def _admin() -> User:
    return User(id="admin-1", username="admin", email="admin@test.com", permissions=list(PRESET_ADMIN))


async def _seed_head(db) -> None:
    await db.projects.insert_one(
        {
            "_id": _PROJECT,
            "name": "advisory-project",
            "team_id": None,
            "default_branch": "main",
            "deleted_branches": [],
            "latest_scan_id": _SCAN,
        }
    )
    await db.scans.insert_one(
        {
            "_id": _SCAN,
            "project_id": _PROJECT,
            "branch": "main",
            "status": SCAN_STATUS_COMPLETED,
            "created_at": datetime.now(timezone.utc),
        }
    )


def _finding(
    _id: str, severity: str, component: str, advisories: list[dict], *, version: str = "1.0.0", **details
) -> dict:
    return {
        "_id": _id,
        "finding_id": f"{component}:{version}",
        "scan_id": _SCAN,
        "project_id": _PROJECT,
        "type": "vulnerability",
        "severity": severity,
        "component": component,
        "version": version,
        "description": "",
        "waived": False,
        "details": {
            "vulnerabilities": advisories,
            "fixed_version": aggregate_fixed_version(advisories, version),
            **details,
        },
    }


async def _call(db, tool: str, **args) -> dict:
    return await ChatToolRegistry().execute_tool(tool, args, _admin(), db)


def _log4j(**details) -> dict:
    """Log4Shell (KEV, ransomware) beside a sibling that is neither in KEV nor fixed."""
    return _finding(
        "f-log4j",
        "CRITICAL",
        "log4j-core",
        [
            {
                "id": _LOG4SHELL,
                "severity": "CRITICAL",
                "cvss_score": 10.0,
                "epss_score": 0.97,
                "epss_percentile": 0.999,
                "in_kev": True,
                "kev_ransomware_use": True,
                "fixed_version": "2.15.0",
                "description": "JNDI lookup remote code execution",
            },
            {
                "id": _LOG4J_DOS,
                "severity": "MEDIUM",
                "cvss_score": 5.9,
                "epss_score": 0.0,
                "epss_percentile": 0.1,
                "fixed_version": None,
                "description": "uncontrolled recursion",
            },
        ],
        epss_score=0.97,
        epss_percentile=0.999,
        exploit_maturity="weaponized",
        in_kev=True,
        **details,
    )


async def test_a_kev_row_is_named_after_its_kev_advisory_not_the_first_by_id(db, database):
    await _seed_head(db)
    # Stored sorted by id, so the MEDIUM advisory comes first.
    await db.findings.insert_one(
        _finding(
            "f-lodash",
            "CRITICAL",
            "lodash",
            [
                {"id": "CVE-2020-28500", "severity": "MEDIUM", "cvss_score": 5.3, "epss_score": 0.01},
                {"id": "CVE-2021-23337", "severity": "CRITICAL", "cvss_score": 7.2, "epss_score": 0.94, "in_kev": True},
            ],
            epss_score=0.94,
            exploit_maturity="active",
            in_kev=True,
        )
    )

    row = (await _call(db, "get_kev_findings"))["findings"][0]

    assert row["cve"] == "CVE-2021-23337"
    assert row["cvss_score"] == 7.2
    assert [(a["id"], a["in_kev"], a["epss_score"]) for a in row["advisories"]] == [
        ("CVE-2021-23337", True, 0.94),
        ("CVE-2020-28500", False, 0.01),
    ]


async def test_a_row_names_the_canonical_cve_and_counts_a_ghsa_alias_once(db, database):
    await _seed_head(db)
    await db.findings.insert_one(
        _finding(
            "f-ghsa",
            "HIGH",
            "minimist",
            [{"id": "GHSA-aaaa-bbbb-cccc", "severity": "HIGH", "aliases": ["CVE-2024-1"]}, {"id": "CVE-2024-1"}],
        )
    )

    row = (await _call(db, "get_scan_findings", project_id=_PROJECT))["findings"][0]

    assert row["cve"] == "CVE-2024-1"
    assert row["cve_count"] == 1


async def test_ranking_breaks_severity_ties_on_the_advisories_cvss(db, database):
    await _seed_head(db)
    await db.findings.insert_many(
        [
            _finding("f-9", "CRITICAL", "nine", [{"id": "CVE-2025-9", "severity": "CRITICAL", "cvss_score": 9.0}]),
            _finding("f-10", "CRITICAL", "ten", [{"id": "CVE-2025-10", "severity": "CRITICAL", "cvss_score": 10.0}]),
        ]
    )

    rows = (await _call(db, "get_scan_findings", project_id=_PROJECT, limit=1))["findings"]

    assert [r["cve"] for r in rows] == ["CVE-2025-10"]


async def test_cve_details_report_the_asked_cve_s_own_kev_epss_and_fix(db, database):
    await _seed_head(db)
    await db.findings.insert_one(_log4j())

    result = await _call(db, "get_cve_details", cve_id=_LOG4J_DOS)

    assert result["in_kev"] is False
    assert result["exploit_maturity"] == "low"
    assert result["epss_score"] == 0.0
    assert result["epss_percentile"] == 0.1
    assert result["cvss_score"] == 5.9
    assert result["severity"] == "MEDIUM"
    assert result["fixed_version"] is None
    assert result["affected_component"] == "log4j-core@1.0.0"


async def test_vulnerability_details_list_the_worst_advisories_first_and_name_the_total(db, database):
    await _seed_head(db)
    advisories = [{"id": f"CVE-2017-000{i}", "severity": "MEDIUM", "fixed_version": "2.0.0"} for i in range(1, 7)]
    advisories.append({"id": "CVE-2020-0001", "severity": "CRITICAL", "fixed_version": None})
    await db.findings.insert_one(_finding("f-jackson", "CRITICAL", "jackson-databind", advisories))

    finding = (await _call(db, "get_vulnerability_details", project_id=_PROJECT, finding_id="f-jackson"))["finding"]

    assert finding["advisories_total"] == 7
    assert len(finding["advisories"]) == 5
    worst = finding["advisories"][0]
    assert (worst["id"], worst["in_kev"], worst["fixed_version"]) == ("CVE-2020-0001", False, None)


async def test_a_cve_is_found_under_the_ghsa_advisory_that_resolved_to_it(db, database):
    await _seed_head(db)
    await db.findings.insert_one(
        _finding(
            "f-ghsa-keyed",
            "CRITICAL",
            "log4j-core",
            [
                {
                    "id": _GHSA,
                    "resolved_cve": _LOG4SHELL,
                    "aliases": [_LOG4SHELL],
                    "severity": "CRITICAL",
                    "description": "JNDI lookup remote code execution",
                }
            ],
        )
    )

    by_cve = await _call(db, "get_findings_by_cve", cve_id=_LOG4SHELL.lower())
    details = await _call(db, "get_cve_details", cve_id=_LOG4SHELL)
    search = await _call(db, "search_findings", query=_LOG4SHELL)

    assert by_cve["total_occurrences"] == 1
    assert by_cve["affected_projects"][0]["findings"][0]["cve"] == _LOG4SHELL
    assert details["description"] == "JNDI lookup remote code execution"
    assert [f["component"] for f in search["findings"]] == ["log4j-core"]


async def test_a_ghsa_advisory_is_found_whatever_casing_the_question_uses(db, database):
    await _seed_head(db)
    await db.findings.insert_one(
        _finding(
            "f-ghsa-only", "HIGH", "left-pad", [{"id": _GHSA, "severity": "HIGH", "description": "prototype pollution"}]
        )
    )

    by_cve = await _call(db, "get_findings_by_cve", cve_id=_GHSA.upper())
    details = await _call(db, "get_cve_details", cve_id=_GHSA.upper())

    assert by_cve["total_occurrences"] == 1
    assert details["description"] == "prototype pollution"


@pytest.mark.parametrize("stored", ["PYSEC-2021-19", "GO-2022-0969", "RUSTSEC-2021-0001"])
async def test_an_osv_advisory_is_found_when_asked_in_lower_case(db, database, stored):
    await _seed_head(db)
    await db.findings.insert_one(_finding("f-osv", "HIGH", "pkg", [{"id": stored, "severity": "HIGH"}]))

    by_cve = await _call(db, "get_findings_by_cve", cve_id=stored.lower())
    details = await _call(db, "get_cve_details", cve_id=stored.lower())

    assert (by_cve["total_occurrences"], details["cve_id"]) == (1, stored)


async def test_findings_by_cve_name_the_asked_cve_on_each_row(db, database):
    await _seed_head(db)
    await db.findings.insert_one(_log4j())

    row = (await _call(db, "get_findings_by_cve", cve_id=_LOG4J_DOS))["affected_projects"][0]["findings"][0]

    assert row["cve"] == _LOG4J_DOS


async def test_auto_fixable_requires_a_fix_for_every_live_critical_and_high_advisory(db, database):
    await _seed_head(db)
    await db.findings.insert_many(
        [
            _finding(
                "f-critical-unfixed",
                "CRITICAL",
                "lodash",
                [
                    {"id": "CVE-2024-0001", "severity": "CRITICAL", "fixed_version": None},
                    {"id": "CVE-2024-0002", "severity": "LOW", "fixed_version": "4.17.21"},
                ],
            ),
            _finding(
                "f-partial",
                "HIGH",
                "axios",
                [
                    {"id": "CVE-2024-0003", "severity": "HIGH", "fixed_version": "1.6.0"},
                    {"id": "CVE-2024-0004", "severity": "LOW", "fixed_version": None},
                ],
            ),
            _finding(
                "f-waived-critical",
                "HIGH",
                "express",
                [
                    {"id": "CVE-2024-0005", "severity": "CRITICAL", "fixed_version": None, "waived": True},
                    {"id": "CVE-2024-0006", "severity": "HIGH", "fixed_version": "4.19.2"},
                ],
            ),
        ]
    )

    rows = (await _call(db, "get_auto_fixable_findings"))["findings"]

    assert {r["component"]: (r["fixed_version"], r["still_open"]) for r in rows} == {
        "axios": ("1.6.0", ["CVE-2024-0004"]),
        "express": ("4.19.2", []),
    }


async def test_kev_list_skips_a_finding_whose_only_kev_advisory_is_waived(db, database):
    await _seed_head(db)
    await db.findings.insert_many(
        [
            _finding(
                "f-kev-waived",
                "MEDIUM",
                "struts",
                [
                    {"id": "CVE-2017-5638", "severity": "CRITICAL", "in_kev": True, "waived": True},
                    {"id": "CVE-2017-0002", "severity": "MEDIUM"},
                ],
                exploit_maturity="active",
                in_kev=True,
            ),
            _log4j(),
        ]
    )

    rows = (await _call(db, "get_kev_findings"))["findings"]

    assert [(r["component"], r["cve"]) for r in rows] == [("log4j-core", _LOG4SHELL)]


async def test_a_waiver_is_not_suggested_for_a_kev_listed_finding(db, database):
    await _seed_head(db)
    await db.findings.insert_one(
        _finding("f-kev", "HIGH", "struts", [{"id": "CVE-2017-5638", "in_kev": True}], in_kev=True)
    )

    result = await _call(db, "suggest_waiver_for_finding", project_id=_PROJECT, finding_id="struts:1.0.0")

    assert result["recommend_waive"] is False
    assert "KEV" in result["suggested_reason"]


async def test_a_waiver_suggestion_reads_the_finding_on_the_head_build(db, database):
    await _seed_head(db)
    # Stored first, so a lookup across the project's builds meets the copy from before the CVE entered KEV.
    older = _finding("f-struts-old", "HIGH", "struts", [{"id": "CVE-2017-5638", "epss_score": 0.001}], epss_score=0.001)
    await db.findings.insert_one({**older, "scan_id": "s-older"})
    await db.findings.insert_one(
        _finding("f-struts", "HIGH", "struts", [{"id": "CVE-2017-5638", "in_kev": True}], in_kev=True)
    )

    result = await _call(db, "suggest_waiver_for_finding", project_id=_PROJECT, finding_id="struts:1.0.0")

    assert result["recommend_waive"] is False
    assert "KEV" in result["suggested_reason"]


async def test_a_waiver_suggestion_reads_the_finding_on_the_build_scan_id_names(db, database):
    await _seed_head(db)
    await db.scans.insert_one(
        {
            "_id": "s-branch",
            "project_id": _PROJECT,
            "branch": "feature/struts",
            "status": SCAN_STATUS_COMPLETED,
            "created_at": datetime.now(timezone.utc),
        }
    )
    finding = _finding("f-struts", "LOW", "struts", [{"id": "CVE-2017-5638", "epss_score": 0.001}], epss_score=0.001)
    await db.findings.insert_one({**finding, "scan_id": "s-branch"})

    on_head = await _call(db, "suggest_waiver_for_finding", project_id=_PROJECT, finding_id="struts:1.0.0")
    on_branch = await _call(
        db, "suggest_waiver_for_finding", project_id=_PROJECT, finding_id="struts:1.0.0", scan_id="s-branch"
    )

    assert on_head == {"error": "Finding not found"}
    assert on_branch["recommend_waive"] is True
    assert (on_branch["scan"]["scan_id"], on_branch["scan"]["is_head"]) == ("s-branch", False)


async def test_remediation_plan_leaves_waived_advisories_out(db, database):
    await _seed_head(db)
    finding = _finding(
        "f-plan",
        "HIGH",
        "spring-web",
        [
            {"id": "CVE-2024-0007", "severity": "CRITICAL", "fixed_version": "3.0.0", "waived": True},
            {"id": "CVE-2024-0008", "severity": "HIGH", "fixed_version": "1.0.1"},
        ],
    )
    await db.findings.insert_one(finding)

    step = (await _call(db, "generate_remediation_plan", project_id=_PROJECT))["plan"][0]

    assert step["target_version"] == "1.0.1"
    assert step["critical_count"] == 0
    assert [r["cve_id"] for r in step["resolves_findings"]] == ["CVE-2024-0008"]


def _jackson_with_one_advisory_waived() -> dict:
    return _finding(
        "f-jackson-waiver",
        "HIGH",
        "jackson-databind",
        [
            {"id": "CVE-2020-0010", "severity": "CRITICAL", "waived": True, "waiver_reason": "not reachable"},
            {"id": "CVE-2020-0011", "severity": "HIGH"},
        ],
    )


async def test_waiver_status_names_a_finding_s_waived_advisories(db, database):
    await _seed_head(db)
    await db.findings.insert_one(_jackson_with_one_advisory_waived())

    result = await _call(db, "get_waiver_status", project_id=_PROJECT, finding_id="jackson-databind:1.0.0")

    assert result["waived"] is False
    assert result["findings"][0]["waived_advisories"] == [{"id": "CVE-2020-0010", "waiver_reason": "not reachable"}]


async def test_waiver_status_answers_for_a_cve_waived_on_one_advisory(db, database):
    await _seed_head(db)
    await db.findings.insert_one(_jackson_with_one_advisory_waived())

    result = await _call(db, "get_waiver_status", project_id=_PROJECT, finding_id="cve-2020-0010")

    assert result["waived"] is True
    assert [(f["component"], f["waived_advisories"][0]["id"]) for f in result["findings"]] == [
        ("jackson-databind", "CVE-2020-0010")
    ]


async def test_waiver_status_is_not_all_waived_when_the_read_left_an_unwaived_finding_out(db, database, monkeypatch):
    monkeypatch.setattr("app.services.chat.tools.registry._WAIVER_STATE_READ", 1)
    await _seed_head(db)
    waived = _jackson_with_one_advisory_waived()
    live = _finding("f-jackson-live", "HIGH", "jackson-core", [{"id": "CVE-2020-0010", "severity": "CRITICAL"}])
    await db.findings.insert_many([waived, live])

    result = await _call(db, "get_waiver_status", project_id=_PROJECT, finding_id="CVE-2020-0010")

    assert (result["waived"], result["waived_count"], result["findings_total"]) == (False, 1, 2)


async def test_waiver_status_answers_per_component_for_a_shared_finding_id(db, database):
    await _seed_head(db)
    license_findings = [
        {
            "_id": f"f-gpl-{component}",
            "finding_id": "LIC-GPL-3.0",
            "scan_id": _SCAN,
            "project_id": _PROJECT,
            "type": "license",
            "severity": "HIGH",
            "component": component,
            "version": "1.0.0",
            "waived": waived,
            "waiver_reason": "internal tool" if waived else None,
        }
        for component, waived in (("readline", True), ("gmp", False))
    ]
    await db.findings.insert_many(license_findings)

    result = await _call(db, "get_waiver_status", project_id=_PROJECT, finding_id="LIC-GPL-3.0")

    assert result["waived"] is False
    assert result["waived_count"] == 1
    assert sorted((f["component"], f["waived"]) for f in result["findings"]) == [("gmp", False), ("readline", True)]


async def test_waiver_status_finds_a_dormant_cve_waiver_by_its_vulnerability_id(db, database):
    await _seed_head(db)
    await db.waivers.insert_one(
        {
            "_id": "w-cve",
            "project_id": _PROJECT,
            "finding_id": None,
            "vulnerability_id": "CVE-2020-0010",
            "reason": "not reachable",
            "expiration_date": None,
        }
    )

    result = await _call(db, "get_waiver_status", project_id=_PROJECT, finding_id="CVE-2020-0010")

    assert (result["waived"], result["waiver_present"], result["suppressing"]) == (False, True, False)


_DORMANT_CVE = "CVE-2020-0010"


def _dormant_waiver(_id: str, expires: datetime | None, *, project_id: str | None = _PROJECT, by_cve=False) -> dict:
    return {
        "_id": _id,
        "project_id": project_id,
        "finding_id": None if by_cve else _DORMANT_CVE,
        "vulnerability_id": _DORMANT_CVE if by_cve else None,
        "reason": "not reachable",
        "expiration_date": expires,
    }


_LAPSED = datetime(2026, 1, 31, tzinfo=timezone.utc)
_LAPSED_EARLIER = datetime(2025, 6, 30, tzinfo=timezone.utc)
_RENEWED = datetime(2099, 1, 31, tzinfo=timezone.utc)


@pytest.mark.parametrize(
    ("waivers", "answer", "waiver_id"),
    [
        pytest.param(
            [_dormant_waiver("w-lapsed", _LAPSED), _dormant_waiver("w-renewed", _RENEWED)],
            "waiver",
            "w-renewed",
            id="renewed-beside-lapsed",
        ),
        pytest.param(
            [_dormant_waiver("w-lapsed", _LAPSED), _dormant_waiver("w-global", None, project_id=None)],
            "waiver",
            "w-global",
            id="global-beside-lapsed-project",
        ),
        pytest.param(
            [_dormant_waiver("w-lapsed", _LAPSED), _dormant_waiver("w-cve", _RENEWED, by_cve=True)],
            "waiver",
            "w-cve",
            id="cve-waiver-beside-lapsed-finding-waiver",
        ),
        pytest.param(
            [_dormant_waiver("w-global", None, project_id=None), _dormant_waiver("w-project", _RENEWED)],
            "waiver",
            "w-project",
            id="project-before-global",
        ),
        pytest.param(
            [_dormant_waiver("w-earlier", _LAPSED_EARLIER), _dormant_waiver("w-later", _LAPSED)],
            "expired_waiver",
            "w-later",
            id="latest-lapsed",
        ),
    ],
)
async def test_waiver_status_off_head_reports_an_active_waiver_before_a_lapsed_one(
    db, database, waivers, answer, waiver_id
):
    await _seed_head(db)
    await db.waivers.insert_many([dict(w) for w in waivers])

    result = await _call(db, "get_waiver_status", project_id=_PROJECT, finding_id=_DORMANT_CVE)

    assert result[answer]["id"] == waiver_id


async def test_waiver_status_without_a_head_build_answers_no_scan_data(db, database):
    await db.projects.insert_one(
        {"_id": _PROJECT, "name": "advisory-project", "team_id": None, "default_branch": "main", "deleted_branches": []}
    )
    await db.waivers.insert_one(_dormant_waiver("w-cve", None))

    result = await _call(db, "get_waiver_status", project_id=_PROJECT, finding_id=_DORMANT_CVE)

    assert result == {"error": "No scan data available"}


async def test_a_row_reads_its_threat_fields_off_the_unwaived_advisories(db, database):
    await _seed_head(db)
    await db.findings.insert_one(
        _finding(
            "f-struts",
            "CRITICAL",
            "struts",
            [
                {"id": "CVE-2017-5638", "severity": "CRITICAL", "in_kev": True, "epss_score": 0.97, "waived": True},
                {"id": "CVE-2017-0002", "severity": "MEDIUM", "epss_score": 0.001, "epss_percentile": 0.2},
            ],
            in_kev=True,
            epss_score=0.97,
            epss_percentile=0.999,
            exploit_maturity="active",
        )
    )

    [row] = (await _call(db, "get_scan_findings", project_id=_PROJECT))["findings"]

    assert "in_kev" not in row
    assert (row["epss_score"], row["epss_percentile"], row["exploit_maturity"]) == (0.001, 0.2, "low")


def _advisory(cve: str, fixed_version: str | None, severity: str = "HIGH") -> dict:
    return {"id": cve, "severity": severity, "fixed_version": fixed_version}


async def _plan(db, **args) -> dict:
    return await _call(db, "generate_remediation_plan", project_id=_PROJECT, **args)


async def test_remediation_plan_gives_each_installed_version_its_own_patch_on_its_major_line(db, database):
    await _seed_head(db)
    advisories = [
        _advisory("CVE-2023-0001", "3.2.20, 4.1.10, 4.2.3"),
        _advisory("CVE-2023-0002", "3.2.19, 4.1.9, 4.2.1"),
    ]
    await db.findings.insert_many(
        [
            _finding("f-django-3", "HIGH", "django", advisories, version="3.2.18"),
            _finding("f-django-4", "HIGH", "django", advisories, version="4.2.0"),
        ]
    )

    plan = (await _plan(db))["plan"]

    assert sorted((s["current_version"], s["target_version"], s["breaking_change_risk"]) for s in plan) == [
        ("3.2.18", "3.2.20", "low"),
        ("4.2.0", "4.2.3", "low"),
    ]


@pytest.mark.parametrize(
    ("installed", "fix_lists", "target"),
    [
        pytest.param("2.0.0", ["2.0.5, 2.1.0-rc1"], "2.0.5", id="stable-before-newer-prerelease"),
        pytest.param("1.9.0", ["2.0.0-rc1", "2.0.0"], "2.0.0", id="release-above-its-prerelease"),
        pytest.param("1.2.0", ["1.2.9rc1", "1.2.10"], "1.2.10", id="pep440-prerelease"),
        pytest.param("2.28-100.el8", ["2.28-151.el8", "2.28-189.5.el8_6"], "2.28-189.5.el8_6", id="rpm-release"),
    ],
)
async def test_remediation_plan_target_covers_every_advisory(db, database, installed, fix_lists, target):
    await _seed_head(db)
    advisories = [_advisory(f"CVE-2024-{i:04d}", fix) for i, fix in enumerate(fix_lists, start=1)]
    await db.findings.insert_one(_finding("f-lib", "HIGH", "lib", advisories, version=installed))

    (step,) = (await _plan(db))["plan"]

    assert step["target_version"] == target


async def test_remediation_plan_counts_only_cves_the_target_fixes(db, database):
    await _seed_head(db)
    await db.findings.insert_many(
        [
            _finding(
                "f-liba",
                "CRITICAL",
                "liba",
                [_advisory("CVE-2024-0001", "1.0.5"), _advisory("CVE-2024-0002", None, "CRITICAL")],
            ),
            _finding(
                "f-libb",
                "CRITICAL",
                "libb",
                [_advisory("CVE-2024-0003", None, "CRITICAL"), _advisory("CVE-2024-0004", None, "CRITICAL")],
            ),
        ]
    )

    result = await _plan(db)

    steps = {s["component"]: s for s in result["plan"]}
    assert (steps["liba"]["resolves_count"], steps["liba"]["unresolved"]) == (1, ["CVE-2024-0002"])
    assert (steps["libb"]["resolves_count"], steps["libb"]["unresolved_count"]) == (0, 2)
    summary = result["summary"]
    assert (summary["cves_resolved"], summary["critical_resolved"], summary["cves_unresolved"]) == (1, 0, 3)


async def test_remediation_plan_counts_a_cve_shared_by_two_installed_versions_once(db, database):
    await _seed_head(db)
    advisories = [_advisory("CVE-2021-23337", "4.17.21")]
    await db.findings.insert_many(
        [
            _finding("f-lodash-15", "HIGH", "lodash", advisories, version="4.17.15"),
            _finding("f-lodash-19", "HIGH", "lodash", advisories, version="4.17.19"),
        ]
    )

    result = await _plan(db)

    assert len(result["plan"]) == 2
    assert result["summary"]["cves_resolved"] == 1


async def test_remediation_plan_steps_are_package_upgrades_and_eol_counts_as_no_cve(db, database):
    await _seed_head(db)
    file_findings = [
        {
            "_id": f"f-{finding_type}",
            "finding_id": f"{finding_type}-1",
            "scan_id": _SCAN,
            "project_id": _PROJECT,
            "type": finding_type,
            "severity": "CRITICAL",
            "component": path,
            "version": None,
            "waived": False,
            "details": {},
        }
        for finding_type, path in (("secret", "src/config.py"), ("iac", "deploy/main.tf"))
    ]
    eol = {
        "_id": "f-eol",
        "finding_id": "EOL-python-3.8",
        "scan_id": _SCAN,
        "project_id": _PROJECT,
        "type": "eol",
        "severity": "HIGH",
        "component": "python",
        "version": "3.8.10",
        "waived": False,
        "details": {"fixed_version": "3.13.1", "eol_date": "2024-10-07", "cycle": "3.8", "recommended_cycle": "3.13"},
    }
    await db.findings.insert_many(
        [*file_findings, eol, _finding("f-lib", "HIGH", "lib", [_advisory("CVE-1", "1.0.1")])]
    )

    result = await _plan(db)

    steps = {s["component"]: s for s in result["plan"]}
    assert set(steps) == {"lib", "python"}
    assert (steps["python"]["target_version"], steps["python"]["resolves_count"]) == ("3.13.1", 0)
    assert result["summary"]["cves_resolved"] == 1


async def test_remediation_plan_summary_covers_the_steps_cut_from_the_plan(db, database):
    await _seed_head(db)
    fixable = [_finding(f"f-fix-{i}", "HIGH", f"lib{i}", [_advisory(f"CVE-2024-000{i}", "1.0.1")]) for i in range(3)]
    unfixable = _finding("f-nofix", "CRITICAL", "nofix", [_advisory("CVE-2024-0009", None, "CRITICAL")])
    await db.findings.insert_many([*fixable, unfixable])

    result = await _plan(db, max_steps=2)

    assert (len(result["plan"]), result["plan_total"]) == (2, 4)
    assert (result["summary"]["cves_resolved"], result["summary"]["steps_without_fix"]) == (3, 1)


async def test_remediation_plan_ranks_a_transitive_critical_fix_before_a_direct_high_one(db, database):
    await _seed_head(db)
    await db.dependencies.insert_one(
        {
            "_id": "d-jackson",
            "scan_id": _SCAN,
            "project_id": _PROJECT,
            "name": "jackson-databind",
            "version": "1.0.0",
            "purl": "pkg:maven/com.fasterxml.jackson.core/jackson-databind@1.0.0",
            "type": "maven",
            "direct": True,
            "direct_inferred": False,
        }
    )
    await db.findings.insert_many(
        [
            _finding("f-jackson", "HIGH", "jackson-databind", [_advisory("CVE-2024-0001", "1.0.1")]),
            _finding(
                "f-log4j",
                "CRITICAL",
                "log4j-core",
                [_advisory(_LOG4SHELL, "2.17.1", "CRITICAL")],
                version="2.14.1",
            ),
        ]
    )

    plan = (await _plan(db))["plan"]

    assert [(s["component"], s["direct_confidence"]) for s in plan] == [
        ("log4j-core", "transitive"),
        ("jackson-databind", "declared"),
    ]


async def test_auto_fixable_names_the_patch_on_the_installed_major_and_flags_major_upgrades(db, database):
    await _seed_head(db)
    await db.findings.insert_many(
        [
            _finding("f-patch", "HIGH", "lib-patch", [_advisory("CVE-2024-0101", "1.2.6, 2.0.1")], version="1.2.0"),
            _finding("f-major", "HIGH", "lib-major", [_advisory("CVE-2024-0102", "2.0.1")], version="1.4.0"),
            _finding("f-behind", "HIGH", "lib-behind", [_advisory("CVE-2024-0103", "2.9.0")], version="3.0.0"),
        ]
    )

    rows = (await _call(db, "get_auto_fixable_findings"))["findings"]

    assert {r["component"]: (r["quick_fix_version"], r["breaking_change_risk"]) for r in rows} == {
        "lib-patch": ("1.2.6", "low"),
        "lib-major": ("2.0.1", "high"),
    }


async def test_auto_fixable_targets_the_critical_and_high_fixes_and_lists_what_the_bump_leaves_open(db, database):
    await _seed_head(db)
    advisories = [
        _advisory("CVE-2024-0201", "1.2.6, 2.0.1"),
        _advisory("CVE-2024-0202", "2.0.1", "MEDIUM"),
        _advisory("CVE-2024-0203", "1.2.3", "LOW"),
    ]
    await db.findings.insert_one(_finding("f-mixed", "HIGH", "lib-mixed", advisories, version="1.2.0"))

    (row,) = (await _call(db, "get_auto_fixable_findings"))["findings"]

    assert (row["quick_fix_version"], row["breaking_change_risk"], row["still_open"]) == (
        "1.2.6",
        "low",
        ["CVE-2024-0202"],
    )


@pytest.mark.parametrize(
    ("severity", "fixed", "epss", "reachability", "recommend", "expiry", "tier"),
    [
        pytest.param("CRITICAL", "2.5.33", 0.5, (True, "symbol"), False, 30, "confirmed", id="reachable-critical-fix"),
        pytest.param("HIGH", "2.5.33", 0.001, (None, None), False, 30, "unknown", id="fix-on-high"),
        pytest.param("HIGH", None, 0.05, (False, "import"), True, 180, "unreachable", id="unreachable-no-fix"),
        pytest.param("MEDIUM", None, 0.5, (None, None), False, 90, "unknown", id="no-supporting-signal"),
        pytest.param("LOW", "2.5.33", 0.5, (None, None), True, 30, "unknown", id="low-bridged-until-upgrade"),
    ],
)
async def test_a_waiver_suggestion_weighs_reachability_and_treats_a_fix_as_a_reason_to_patch(
    db, database, severity, fixed, epss, reachability, recommend, expiry, tier
):
    await _seed_head(db)
    reachable, level = reachability
    finding = _finding("f-struts", severity, "struts", [_advisory("CVE-2023-50164", fixed, severity)], epss_score=epss)
    await db.findings.insert_one({**finding, "reachable": reachable, "reachability_level": level})

    result = await _call(db, "suggest_waiver_for_finding", project_id=_PROJECT, finding_id="struts:1.0.0")

    assert (result["recommend_waive"], result["suggested_expiry_days"]) == (recommend, expiry)
    assert result["signals"]["reachability"] == tier
    assert "a fix is available" not in result["suggested_reason"]
    assert ("not reachable" in result["suggested_reason"]) is (tier == "unreachable")
