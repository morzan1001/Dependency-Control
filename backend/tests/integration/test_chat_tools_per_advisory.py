"""Chat/MCP tools answer per advisory: a vulnerability finding holds every advisory of one
component@version, and its details carry maxima over all of them.

The consumer is a language model relaying the answer, so a CVE id paired with a sibling's KEV
status, EPSS or fix reads as a confident, wrong security verdict.
"""

from datetime import datetime, timezone

import pytest

from app.core.constants import SCAN_STATUS_COMPLETED
from app.models.user import User
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


def _finding(_id: str, severity: str, component: str, advisories: list[dict], **details) -> dict:
    return {
        "_id": _id,
        "finding_id": f"{component}:1.0.0",
        "scan_id": _SCAN,
        "project_id": _PROJECT,
        "type": "vulnerability",
        "severity": severity,
        "component": component,
        "version": "1.0.0",
        "description": "",
        "waived": False,
        "details": {"vulnerabilities": advisories, **details},
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
        fixed_version="2.15.0",
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

    row = (await _call(db, "get_project_findings", project_id=_PROJECT))["findings"][0]

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

    rows = (await _call(db, "get_project_findings", project_id=_PROJECT, limit=1))["findings"]

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
    await db.findings.insert_one(
        _finding("f-jackson", "CRITICAL", "jackson-databind", advisories, fixed_version="2.0.0")
    )

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
                fixed_version="4.17.21",
            ),
            _finding(
                "f-partial",
                "HIGH",
                "axios",
                [
                    {"id": "CVE-2024-0003", "severity": "HIGH", "fixed_version": "1.6.0"},
                    {"id": "CVE-2024-0004", "severity": "LOW", "fixed_version": None},
                ],
                fixed_version="1.6.0",
            ),
            _finding(
                "f-waived-critical",
                "HIGH",
                "express",
                [
                    {"id": "CVE-2024-0005", "severity": "CRITICAL", "fixed_version": None, "waived": True},
                    {"id": "CVE-2024-0006", "severity": "HIGH", "fixed_version": "4.19.2"},
                ],
                fixed_version="4.19.2",
            ),
        ]
    )

    rows = (await _call(db, "get_auto_fixable_findings"))["findings"]

    assert {r["component"]: r["still_open"] for r in rows} == {"axios": ["CVE-2024-0004"], "express": []}


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
        fixed_version="1.0.1, 3.0.0",
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
