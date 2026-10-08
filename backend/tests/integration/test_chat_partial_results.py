"""A chat tool that cuts a list names the rows it kept and their population, and reads only what it answers with."""

from datetime import datetime, timedelta, timezone

import pytest

from app.core.constants import DETAILS_KEY_IN_KEV, DETAILS_KEY_KEV_RANSOMWARE, SCAN_STATUS_COMPLETED
from app.models.user import User
from app.services.chat.tools import ChatToolRegistry
from app.services.chat.tools._helpers import _serialize_finding_for_llm
from tests.helpers.permission_presets import PRESET_ADMIN, PRESET_USER

_DATABASES = [
    pytest.param("attrappe", id="attrappe"),
    pytest.param("real-mongo", marks=pytest.mark.live_mongo, id="real-mongo"),
]

pytestmark = pytest.mark.asyncio

_NOW = datetime.now(timezone.utc).replace(microsecond=0)
_PROJECT = "p-partial-results"
_HEAD = "scan-partial-head"
# An OSV advisory text runs to tens of kilobytes; a chat answer quotes none of it.
_ADVISORY_TEXT_BYTES = 32_000
_HEAVY_FINDINGS = 10

_RICH_FINDING = {
    "_id": f"{_HEAD}:jackson-databind",
    "finding_id": "jackson-databind:2.9.8",
    "scan_id": _HEAD,
    "project_id": _PROJECT,
    "type": "vulnerability",
    "severity": "CRITICAL",
    "component": "jackson-databind",
    "version": "2.9.8",
    "description": "Deserialization of untrusted data",
    "waived": False,
    "first_seen_at": _NOW - timedelta(days=90),
    "scanners": ["grype", "trivy"],
    "details": {
        "epss_score": 0.91,
        "fixed_version": "2.9.10.8",
        "exploit_maturity": "active",
        "risk_score": 88.0,
        DETAILS_KEY_IN_KEV: True,
        "vulnerabilities": [
            {
                "id": "GHSA-57j2-w4cx-62h2",
                "resolved_cve": "CVE-2020-36518",
                "severity": "CRITICAL",
                "cvss_score": 9.8,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "epss_score": 0.91,
                "epss_percentile": 0.99,
                "risk_score": 88.0,
                DETAILS_KEY_IN_KEV: True,
                DETAILS_KEY_KEV_RANSOMWARE: True,
                "fixed_version": "2.9.10.8",
                "references": ["https://nvd.nist.gov/vuln/detail/CVE-2020-36518", "https://github.com/advisories/x"],
                "waived": False,
                "description": "Deeply nested JSON exhausts the stack.",
                "scanners": ["grype"],
            },
            {
                "id": "GHSA-cjjf-94ff-43w7",
                "aliases": ["CVE-2019-12384"],
                "severity": "HIGH",
                "cvss_score": 7.5,
                "epss_score": 0.2,
                "epss_percentile": 0.7,
                "fixed_version": "2.9.9.1",
                "references": ["https://nvd.nist.gov/vuln/detail/CVE-2019-12384"],
                "description": "Polymorphic typing allows remote code execution.",
            },
            {
                "id": "CVE-2020-99999",
                "severity": "CRITICAL",
                "epss_score": 0.97,
                "fixed_version": "2.9.10.8",
                "waived": True,
            },
        ],
    },
}


_WAIVED_OUTDATED = {
    "_id": f"{_HEAD}:spring-core",
    "finding_id": "spring-core:5.2.0",
    "scan_id": _HEAD,
    "project_id": _PROJECT,
    "type": "outdated",
    "severity": "LOW",
    "component": "spring-core",
    "version": "5.2.0",
    "description": "Newer version available",
    "waived": True,
    "waiver_reason": "Pinned until the Boot 3 migration",
    "details": {"fixed_version": "6.1.14"},
}


def _heavy_finding(n: int) -> dict:
    return {
        "_id": f"{_HEAD}:lib-{n}",
        "finding_id": f"lib-{n}:1.0.0",
        "scan_id": _HEAD,
        "project_id": _PROJECT,
        "type": "vulnerability",
        "severity": "CRITICAL",
        "component": f"lib-{n}",
        "version": "1.0.0",
        "details": {
            "vulnerabilities": [
                {"id": f"CVE-2026-{n:05d}", "severity": "CRITICAL", "description": "x" * _ADVISORY_TEXT_BYTES}
            ]
        },
    }


async def _seed_head(db, findings: list[dict]) -> None:
    await db.projects.insert_one(
        {
            "_id": _PROJECT,
            "name": _PROJECT,
            "default_branch": "main",
            "deleted_branches": [],
            "latest_scan_id": _HEAD,
        }
    )
    await db.scans.insert_one(
        {"_id": _HEAD, "project_id": _PROJECT, "branch": "main", "status": SCAN_STATUS_COMPLETED, "created_at": _NOW}
    )
    await db.findings.insert_many(findings)


async def _call(db, tool: str, **args) -> dict:
    admin = User(id="admin-1", username="admin", email="admin@test.com", permissions=list(PRESET_ADMIN))
    return await ChatToolRegistry().execute_tool(tool, args, admin, db)


@pytest.mark.parametrize("database", _DATABASES)
async def test_neglected_projects_list_the_longest_unscanned_first_with_their_total(db, database):
    # Natural order opens with the stale project closest to the threshold.
    await db.projects.insert_many(
        [
            {"_id": "stale-20d", "name": "stale-20d", "last_scan_at": _NOW - timedelta(days=20)},
            {"_id": "fresh", "name": "fresh", "last_scan_at": _NOW - timedelta(days=1)},
            {"_id": "stale-60d", "name": "stale-60d", "last_scan_at": _NOW - timedelta(days=60)},
            {"_id": "stale-200d", "name": "stale-200d", "last_scan_at": _NOW - timedelta(days=200)},
            {"_id": "never", "name": "never"},
        ]
    )

    result = await _call(db, "get_projects_without_recent_scan", days=14, limit=2)

    assert [p["project_id"] for p in result["projects"]] == ["never", "stale-200d"]
    assert (result.get("projects_total"), result.get("_bounded_read")) == (4, True)


@pytest.mark.parametrize("database", _DATABASES)
async def test_neglected_projects_list_only_the_callers_projects(db, database):
    member = "member-1"
    await db.projects.insert_many(
        [
            {
                "_id": "own-stale",
                "name": "own-stale",
                "last_scan_at": _NOW - timedelta(days=60),
                "members": [{"user_id": member, "role": "viewer"}],
            },
            {"_id": "foreign-never", "name": "foreign-never", "members": []},
        ]
    )
    caller = User(id=member, username="member", email="member@test.com", permissions=list(PRESET_USER))

    result = await ChatToolRegistry().execute_tool("get_projects_without_recent_scan", {"days": 14}, caller, db)

    assert [p["project_id"] for p in result["projects"]] == ["own-stale"]
    assert result["projects_total"] == 1


@pytest.mark.live_mongo
async def test_a_ranked_read_leaves_the_advisory_text_on_the_server(db):
    await _seed_head(db, [_heavy_finding(n) for n in range(_HEAVY_FINDINGS)])
    await db.command({"profile": 2})

    result = await _call(db, "get_scan_findings", project_id=_PROJECT, limit=3)

    await db.command({"profile": 0})
    reads = await db["system.profile"].find({"ns": f"{db.name}.findings", "op": "query"}).to_list(None)
    assert len(result["findings"]) == 3
    assert max(r["responseLength"] for r in reads) < _ADVISORY_TEXT_BYTES


@pytest.mark.parametrize("database", _DATABASES)
async def test_ranked_tools_answer_from_the_slim_read_as_from_the_full_finding(db, database):
    await _seed_head(db, [_RICH_FINDING])

    scan_rows = (await _call(db, "get_scan_findings", project_id=_PROJECT))["findings"]
    stale_rows = (await _call(db, "get_stale_findings", days_open=30))["findings"]
    fixable_rows = (await _call(db, "get_auto_fixable_findings"))["findings"]

    expected = _serialize_finding_for_llm(_RICH_FINDING)
    assert {"cve", "cvss_score", "references", "advisories", "epss_percentile"} <= expected.keys()
    assert [row.items() >= expected.items() for row in (*scan_rows, *stale_rows, *fixable_rows)] == [True] * 3
    # Live Mongo hands datetimes back naive, the attrappe keeps the offset.
    assert stale_rows[0]["first_seen_at"].startswith(_RICH_FINDING["first_seen_at"].strftime("%Y-%m-%dT%H:%M:%S"))
    assert fixable_rows[0]["quick_fix_version"] == "2.9.10.8"


@pytest.mark.parametrize("database", _DATABASES)
async def test_a_waived_finding_without_advisories_keeps_its_waiver_reason_and_fix_in_the_slim_read(db, database):
    await _seed_head(db, [_WAIVED_OUTDATED])

    rows = (await _call(db, "get_scan_findings", project_id=_PROJECT))["findings"]

    expected = _serialize_finding_for_llm(_WAIVED_OUTDATED)
    assert {"waiver_reason", "fixed_version"} <= expected.keys()
    assert [row.items() >= expected.items() for row in rows] == [True]
