"""The shared-vulnerability card joins projects on each live advisory's CVE identity, not its raw id."""

from datetime import datetime, timezone

import pytest

from app.api.v1.helpers.analytics import gather_cross_project_data
from app.services.analytics.scopes import read_scope_projects

pytestmark = [pytest.mark.asyncio, pytest.mark.live_mongo]

_LODASH_CVE = "CVE-2021-23337"
_LODASH_GHSA = "GHSA-35jh-r3h4-6jhm"


def _finding(_id: str, project_id: str, advisories: list[dict], waived: bool = False, kind="vulnerability") -> dict:
    return {
        "_id": _id,
        "scan_id": f"s-{project_id}",
        "project_id": project_id,
        "type": kind,
        "component": "lodash",
        "waived": waived,
        "details": {"vulnerabilities": advisories},
    }


async def _projects(db, *project_ids: str) -> None:
    for project_id in project_ids:
        await db.projects.insert_one(
            {"_id": project_id, "name": project_id, "latest_scan_id": f"s-{project_id}", "default_branch": "main"}
        )
        await db.scans.insert_one(
            {
                "_id": f"s-{project_id}",
                "project_id": project_id,
                "branch": "main",
                "status": "completed",
                "created_at": datetime(2026, 9, 5, tzinfo=timezone.utc),
                "stats": {"critical": 0, "high": 0},
            }
        )


async def _cves_by_project(db) -> dict[str, list[str]]:
    data = await gather_cross_project_data(await read_scope_projects(db, {}), "current", db)
    assert data is not None
    return {p["project_id"]: p["cves"] for p in data["projects"]}


async def test_a_ghsa_and_its_cve_are_one_shared_vulnerability(db):
    await _projects(db, "current", "p1", "p2")
    await db.findings.insert_many(
        [
            _finding("f1", "p1", [{"id": _LODASH_CVE}]),
            _finding("f2", "p1", [{"id": _LODASH_GHSA, "resolved_cve": _LODASH_CVE}]),
            _finding("f3", "p2", [{"id": _LODASH_GHSA, "aliases": [_LODASH_CVE]}]),
        ]
    )

    assert await _cves_by_project(db) == {"current": [], "p1": [_LODASH_CVE], "p2": [_LODASH_CVE]}


async def test_waived_advisories_and_other_findings_are_not_shared(db):
    await _projects(db, "current", "p1", "p2")
    await db.findings.insert_many(
        [
            _finding("f1", "p1", [{"id": "CVE-2026-0001"}], waived=True),
            _finding("f2", "p1", [{"id": "CVE-2026-0002", "waived": True}, {"id": _LODASH_CVE}]),
            _finding("f3", "p2", [{"id": "CVE-2026-0003"}], kind="license"),
            _finding("f4", "p2", []),
        ]
    )

    assert await _cves_by_project(db) == {"current": [], "p1": [_LODASH_CVE], "p2": []}
