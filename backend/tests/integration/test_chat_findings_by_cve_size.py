import json
from datetime import datetime, timezone

import pytest

from app.core.constants import SCAN_STATUS_COMPLETED
from app.services.chat.tools import ChatToolRegistry
from app.services.chat.tools._helpers import MAX_TOOL_RESULT_BYTES
from tests.helpers.auth import make_admin
from tests.helpers.databases import DATABASES

pytestmark = [pytest.mark.asyncio, pytest.mark.parametrize("database", DATABASES)]

_CVE = "CVE-2021-44228"
_DESCRIPTION = "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP endpoints. " * 5
_REFERENCES = [f"https://nvd.nist.gov/vuln/detail/{_CVE}", "https://logging.apache.org/log4j/2.x/security.html"]


async def _seed_project(db, project_id: str, occurrences: int) -> None:
    scan_id = f"{project_id}-head"
    await db.projects.insert_one(
        {
            "_id": project_id,
            "name": f"name-{project_id}",
            "default_branch": "main",
            "deleted_branches": [],
            "latest_scan_id": scan_id,
        }
    )
    await db.scans.insert_one(
        {
            "_id": scan_id,
            "project_id": project_id,
            "branch": "main",
            "status": SCAN_STATUS_COMPLETED,
            "created_at": datetime.now(timezone.utc),
        }
    )
    await db.findings.insert_many(
        [
            {
                "_id": f"{project_id}-{i}",
                "finding_id": f"module-{i}/log4j-core:2.14.1",
                "scan_id": scan_id,
                "project_id": project_id,
                "type": "vulnerability",
                "severity": "CRITICAL",
                "component": f"module-{i}/log4j-core",
                "version": "2.14.1",
                "description": _DESCRIPTION,
                "waived": False,
                "details": {
                    "fixed_version": "2.15.0",
                    "vulnerabilities": [
                        {
                            "id": _CVE,
                            "severity": "CRITICAL",
                            "cvss_score": 10.0,
                            "epss_score": 0.97,
                            "in_kev": True,
                            "fixed_version": "2.15.0",
                            "references": _REFERENCES,
                        }
                    ],
                },
            }
            for i in range(occurrences)
        ]
    )


async def _by_cve(db, **args) -> dict:
    return await ChatToolRegistry().execute_tool("get_findings_by_cve", {"cve_id": _CVE, **args}, make_admin(), db)


def _counts(result: dict) -> list[tuple[str, int]]:
    return [(p["project_name"], p["occurrences"]) for p in result["affected_projects"]]


@pytest.mark.parametrize("occurrences", [12, 40], ids=["all-read", "more-than-read"])
async def test_a_cve_with_more_occurrences_than_fit_still_names_its_project(db, database, occurrences):
    await _seed_project(db, "p-big", occurrences)

    result = await _by_cve(db)

    assert _counts(result) == [("name-p-big", occurrences)]
    assert 0 < len(result["affected_projects"][0]["findings"]) < occurrences
    assert (result["project_count"], result["total_occurrences"]) == (1, occurrences)
    assert "project_id" in result["_occurrences_note"]
    assert len(json.dumps(result, default=str, ensure_ascii=False).encode()) <= MAX_TOOL_RESULT_BYTES


async def test_every_affected_project_is_listed_with_its_count_most_affected_first(db, database):
    await _seed_project(db, "p-big", 30)
    await _seed_project(db, "p-few", 2)
    await _seed_project(db, "p-one", 1)

    result = await _by_cve(db)

    assert _counts(result) == [("name-p-big", 30), ("name-p-few", 2), ("name-p-one", 1)]
    assert (result["project_count"], result["total_occurrences"]) == (3, 33)
    assert len(json.dumps(result, default=str, ensure_ascii=False).encode()) <= MAX_TOOL_RESULT_BYTES


async def test_a_project_id_narrows_the_answer_to_that_projects_occurrences(db, database):
    await _seed_project(db, "p-big", 30)
    await _seed_project(db, "p-few", 2)

    result = await _by_cve(db, project_id="p-few")

    assert _counts(result) == [("name-p-few", 2)]
    assert {f["component"] for f in result["affected_projects"][0]["findings"]} == {
        "module-0/log4j-core",
        "module-1/log4j-core",
    }
    assert "_occurrences_note" not in result


async def test_a_cve_in_more_projects_than_fit_counts_them_all_and_lists_the_most_affected(db, database):
    await _seed_project(db, "p-00-most", 3)
    for i in range(1, 60):
        await _seed_project(db, f"p-{i:02d}", 1)

    result = await _by_cve(db)

    assert (result["project_count"], result["total_occurrences"]) == (60, 62)
    assert _counts(result)[0] == ("name-p-00-most", 3)
    assert len(json.dumps(result, default=str, ensure_ascii=False).encode()) <= MAX_TOOL_RESULT_BYTES
