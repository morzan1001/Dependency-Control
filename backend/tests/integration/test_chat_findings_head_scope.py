"""search_findings and get_cve_details read the head builds, as get_findings_by_cve and the other estate tools do."""

from datetime import datetime, timedelta, timezone

import pytest

from app.core.constants import SCAN_STATUS_COMPLETED
from app.core.init_db import create_indexes
from app.models.user import User
from app.services.chat.tools import ChatToolRegistry
from tests.helpers.databases import DATABASES
from tests.helpers.permission_presets import PRESET_ADMIN, PRESET_USER

pytestmark = pytest.mark.asyncio

_PROJECT = "p-head-scope"
_PROJECT_NAME = "head-scope-project"
_HEAD = "scan-head"
_SUPERSEDED = "scan-superseded"
_NOW = datetime.now(timezone.utc).replace(microsecond=0)
_FIXED_CVE = "CVE-2021-44228"
_OPEN_CVE = "CVE-2021-45105"
_SUPERSEDED_NOISE = 30
_MEMBER = "member-1"
_FOREIGN_PROJECT = "p-foreign"
_FOREIGN_HEAD = "scan-foreign-head"
_FOREIGN_CVE = "CVE-2022-23302"


def _finding(scan_id: str, component: str, cve: str, project_id: str = _PROJECT) -> dict:
    return {
        "_id": f"{scan_id}:{component}",
        "finding_id": f"{component}:1.0.0",
        "scan_id": scan_id,
        "project_id": project_id,
        "type": "vulnerability",
        "severity": "CRITICAL",
        "component": component,
        "version": "1.0.0",
        "description": "",
        "waived": False,
        "details": {"vulnerabilities": [{"id": cve, "severity": "CRITICAL", "description": f"{cve} advisory"}]},
    }


async def _seed(db) -> None:
    """log4j-core was fixed after the superseded build; a deleted project left its findings behind."""
    await db.projects.insert_one(
        {
            "_id": _PROJECT,
            "name": _PROJECT_NAME,
            "default_branch": "main",
            "deleted_branches": [],
            "latest_scan_id": _HEAD,
            "members": [{"user_id": _MEMBER, "role": "viewer"}],
        }
    )
    await db.scans.insert_many(
        [
            {
                "_id": scan_id,
                "project_id": _PROJECT,
                "branch": "main",
                "status": SCAN_STATUS_COMPLETED,
                "created_at": created_at,
            }
            for scan_id, created_at in ((_SUPERSEDED, _NOW - timedelta(days=30)), (_HEAD, _NOW))
        ]
    )
    await db.findings.insert_many(
        [
            _finding(_SUPERSEDED, "log4j-core", _FIXED_CVE),
            _finding(_HEAD, "log4j-api", _OPEN_CVE),
            _finding("scan-of-deleted-project", "log4j-core", _FIXED_CVE, project_id="p-deleted"),
        ]
    )


async def _seed_foreign_project(db) -> None:
    """A head build the member is not admitted to, carrying a log4j finding and a CVE only it has."""
    await db.projects.insert_one(
        {
            "_id": _FOREIGN_PROJECT,
            "name": "foreign-project",
            "default_branch": "main",
            "deleted_branches": [],
            "latest_scan_id": _FOREIGN_HEAD,
            "members": [],
        }
    )
    await db.scans.insert_one(
        {
            "_id": _FOREIGN_HEAD,
            "project_id": _FOREIGN_PROJECT,
            "branch": "main",
            "status": SCAN_STATUS_COMPLETED,
            "created_at": _NOW,
        }
    )
    await db.findings.insert_one(_finding(_FOREIGN_HEAD, "log4j-1.2", _FOREIGN_CVE, project_id=_FOREIGN_PROJECT))


async def _call(db, tool: str, **args) -> dict:
    admin = User(id="admin-1", username="admin", email="admin@test.com", permissions=list(PRESET_ADMIN))
    return await ChatToolRegistry().execute_tool(tool, args, admin, db)


async def _call_as_member(db, tool: str, **args) -> dict:
    member = User(id=_MEMBER, username="member", email="member@test.com", permissions=list(PRESET_USER))
    return await ChatToolRegistry().execute_tool(tool, args, member, db)


@pytest.mark.parametrize("database", DATABASES)
async def test_a_search_lists_only_the_head_builds_findings(db, database):
    await _seed(db)

    result = await _call(db, "search_findings", query="log4j")

    assert [(f["component"], f["project_name"]) for f in result["findings"]] == [("log4j-api", _PROJECT_NAME)]
    assert result["findings_total"] == 1


@pytest.mark.parametrize("database", DATABASES)
async def test_cve_details_agree_with_findings_by_cve_on_a_cve_fixed_since(db, database):
    await _seed(db)

    by_cve = await _call(db, "get_findings_by_cve", cve_id=_FIXED_CVE)
    details = await _call(db, "get_cve_details", cve_id=_FIXED_CVE)

    assert by_cve["total_occurrences"] == 0
    assert details == {"error": f"{_FIXED_CVE} not found in any of your projects' scan data"}


@pytest.mark.parametrize("database", DATABASES)
async def test_a_member_reads_no_head_build_of_a_project_outside_their_scope(db, database):
    await _seed(db)
    await _seed_foreign_project(db)

    search = await _call_as_member(db, "search_findings", query="log4j")
    details = await _call_as_member(db, "get_cve_details", cve_id=_FOREIGN_CVE)

    assert [(f["component"], f["project_name"]) for f in search["findings"]] == [("log4j-api", _PROJECT_NAME)]
    assert details == {"error": f"{_FOREIGN_CVE} not found in any of your projects' scan data"}


@pytest.mark.live_mongo
async def test_a_term_matching_nothing_examines_only_the_head_builds_findings(db):
    await create_indexes(db)
    await _seed(db)
    await db.findings.insert_many(
        [_finding(_SUPERSEDED, f"noise-{n}", f"CVE-2020-{n:04d}") for n in range(_SUPERSEDED_NOISE)]
    )
    await db.command({"profile": 2})

    await _call(db, "search_findings", query="no-such-package")
    await _call(db, "get_cve_details", cve_id="CVE-1999-0001")

    await db.command({"profile": 0})
    reads = await db["system.profile"].find({"ns": f"{db.name}.findings"}).to_list(None)
    assert [(r["op"], r["docsExamined"]) for r in reads] == [("query", 1), ("query", 1)]
